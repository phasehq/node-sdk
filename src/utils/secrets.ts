
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


const REFERENCE_REGEX =
  /\${(?:(?<env>[^.\/}]+)\.)?(?:(?<path>[^}]+)\/)?(?<key>[^}]+)}/g;

export const normalizeKey = (env: string, path: string, key: string) =>
  `${env.toLowerCase()}:${path.replace(/\/+$/, "")}:${key}`;

export function parseSecretReference(reference: string): SecretReference {
  const parserRegex = new RegExp(REFERENCE_REGEX.source);
  const match = parserRegex.exec(reference);

  if (!match?.groups) {
    throw new Error(`Invalid secret reference format: ${reference}`);
  }

  let { env, path, key } = match.groups;
  console.log("reference:", reference, env, path, key);
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
  console.log("all references", references);
  let resolvedValue = value;

  for (const ref of references) {
    try {
      const {
        env: refEnv,
        path: refPath,
        key: refKey,
      } = parseSecretReference(ref[0]);

      const targetEnv = refEnv || currentEnv;
      const targetPath = refPath || currentPath;

      const cacheKey = normalizeKey(targetEnv, targetPath, refKey);

      console.log("util cacheKey", cacheKey);

      console.log("resolving", ref, targetEnv, targetPath, refKey);

      
      if (resolutionStack.has(cacheKey)) {
        throw new Error(`Circular reference detected: ${cacheKey}`);
      }

      // If we already have a resolved value, use it
      if (!cache.has(cacheKey)) {
        resolutionStack.add(cacheKey); // Add before calling fetcher
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
          resolutionStack.delete(cacheKey); // Ensure cleanup even if an error occurs
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
