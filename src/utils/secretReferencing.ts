import { Secret } from "../types";

type SecretReference = {
  app: string | null;
  env: string | null;
  path: string;
  key: string;
};

export type SecretFetcher = (
  env: string,
  path: string,
  key: string,
  app?: string | null
) => Promise<Secret>;

// Regex pattern for secret references
const REFERENCE_REGEX =
  /\${(?:(?<app>[^:}]+)::)?(?:(?<env>[^.\/}]+)\.)?(?:(?<path>[^}]+)\/)?(?<key>[^}]+)}/g;

export const normalizeKey = (env: string, path: string, key: string, app?: string) =>
  `${app ? `${app}:` : ''}${env.toLowerCase()}:${path.replace(/\/+$/, "")}:${key}`;

export function parseSecretReference(reference: string): SecretReference {
  const match = new RegExp(REFERENCE_REGEX.source).exec(reference);
  if (!match?.groups) {
    throw new Error(`Invalid secret reference format: ${reference}`);
  }

  const { app: appMatch, env: envMatch, path: pathMatch, key: keyMatch } = match.groups;
  const app = appMatch?.trim() || null;
  const env = envMatch?.trim() || null;
  const key = keyMatch.trim();
  const path = pathMatch ? `/${pathMatch.replace(/\.+/g, "/")}`.replace(/\/+/g, "/") : "/";

  return { app, env, path, key };
}

export async function resolveSecretReferences(
  value: string,
  currentEnv: string,
  currentPath: string,
  fetcher: SecretFetcher,
  currentApp?: string | null,
  cache = new Map<string, string>(),
  resolutionStack = new Set<string>()
): Promise<string> {
  // Skip processing if there are no references to resolve
  if (!value.includes("${")) {
    return value;
  }

  const references = Array.from(value.matchAll(REFERENCE_REGEX));
  let resolvedValue = value;

  for (const ref of references) {
    try {
      const {
        app: refApp,
        env: refEnv,
        path: refPath,
        key: refKey,
      } = parseSecretReference(ref[0]);
      
      const targetApp = refApp || currentApp;
      const targetEnv = refEnv || currentEnv;
      const targetPath = refPath || currentPath || "/";
      
      // Create cache key from normalized values
      const cacheKey = normalizeKey(
        targetEnv || "", 
        targetPath, 
        refKey, 
        targetApp || undefined
      );

      // Check for circular references
      if (resolutionStack.has(cacheKey)) {
        throw new Error(`Circular reference detected: ${ref[0]} → ${cacheKey}`);
      }

      // Resolve the reference if not in cache
      if (!cache.has(cacheKey)) {
        resolutionStack.add(cacheKey);
        try {
          // Fetch the referenced secret
          const secret = await fetcher(targetEnv || "", targetPath, refKey, targetApp);
          
          // Recursively resolve any references in the secret value
          const resolvedSecretValue = await resolveSecretReferences(
            secret.value,
            targetEnv,
            targetPath,
            fetcher,
            targetApp,
            cache,
            resolutionStack
          );
          
          cache.set(cacheKey, resolvedSecretValue);
        } catch (error: any) {
          throw new Error(`Failed to resolve reference ${ref[0]}: ${error.message || error}`);
        } finally {
          resolutionStack.delete(cacheKey);
        }
      }

      // Replace the reference with its resolved value
      resolvedValue = resolvedValue.replace(ref[0], cache.get(cacheKey)!);
    } catch (error: any) {
      if (!error.message?.includes('Failed to resolve reference')) {
        error = new Error(`Error resolving reference ${ref[0]}: ${error.message || error}`);
      }
      throw error;
    }
  }

  return resolvedValue;
}
