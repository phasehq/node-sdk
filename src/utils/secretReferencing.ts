import { Secret } from "../types";

type SecretReference = {
  env: string | null;
  path: string | null;
  key: string;
};

export type SecretFetcher = (
  env: string,
  path: string,
  key: string
) => Promise<Secret>;

// Regex pattern for secret references
const REFERENCE_REGEX =
  /\${(?:(?<env>[^.\/}]+)\.)?(?:(?<path>[^}]+)\/)?(?<key>[^}]+)}/g;

export const normalizeKey = (env: string, path: string, key: string) =>
  `${env.toLowerCase()}:${path.replace(/\/+$/, "")}:${key}`;

export function parseSecretReference(reference: string): SecretReference {
  const match = new RegExp(REFERENCE_REGEX.source).exec(reference);
  if (!match?.groups) {
    throw new Error(`Invalid secret reference format: ${reference}`);
  }

  let { env, path, key } = match.groups;
  env = env?.trim() || "";
  key = key.trim();
  path = path ? `/${path.replace(/\.+/g, "/")}`.replace(/\/+/g, "/") : "/";

  return { env, path, key };
}

export async function resolveSecretReferences(
  value: string,
  currentEnv: string,
  currentPath: string,
  fetcher: SecretFetcher,
  cache: Map<string, string> = new Map(),
  resolutionStack: Set<string> = new Set()
): Promise<string> {
  const references = Array.from(value.matchAll(REFERENCE_REGEX));
  let resolvedValue = value;

  for (const ref of references) {
    try {
      const { env: refEnv, path: refPath, key: refKey } = parseSecretReference(ref[0]);
      const targetEnv = refEnv || currentEnv;
      const targetPath = refPath || currentPath;
      const cacheKey = normalizeKey(targetEnv, targetPath, refKey);

      if (resolutionStack.has(cacheKey)) {
        throw new Error(`Circular reference detected: ${cacheKey}`);
      }

      if (!cache.has(cacheKey)) {
        resolutionStack.add(cacheKey);
        try {
          const secret = await fetcher(targetEnv, targetPath, refKey);
          const resolvedSecretValue = await resolveSecretReferences(
            secret.value,
            targetEnv,
            targetPath,
            fetcher,
            cache,
            resolutionStack
          );
          cache.set(cacheKey, resolvedSecretValue);
        } finally {
          resolutionStack.delete(cacheKey);
        }
      }

      resolvedValue = resolvedValue.replace(ref[0], cache.get(cacheKey)!);
    } catch (error) {
      console.error(`Error resolving reference ${ref[0]}:`, error);
      throw error;
    }
  }

  return resolvedValue;
}
