import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Suffix marking an INGEST_TOKENS entry as scoped to the OTLP receiver
 * (POST /v1/traces) only — the "one token per app, scoped to /v1/traces"
 * model in docs/otel-genai-integration-guide.md. An entry `secret@otel`
 * authenticates OTLP app-team exports but nothing else (no /v1/events,
 * no /v1/coverage); unsuffixed entries keep full collector access.
 */
export const OTEL_TOKEN_SCOPE_SUFFIX = "@otel";

/** Constant-time comparison against every token in `allowed`. */
function matchesAny(candidate: string, allowed: string[]): boolean {
  const candidateHash = createHash("sha256").update(candidate).digest();
  return allowed.some((token) =>
    timingSafeEqual(candidateHash, createHash("sha256").update(token).digest()),
  );
}

/**
 * Constant-time bearer token check for full-access (collector) routes.
 * `@otel`-scoped entries are excluded here: they authenticate OTLP exports
 * only, and the literal scoped string is not itself a usable token.
 * Both sides are SHA-256 hashed first so the comparison neither leaks
 * token length nor short-circuits on content.
 */
export function isValidToken(candidate: string, allowedTokens: string[]): boolean {
  return matchesAny(
    candidate,
    allowedTokens.filter((t) => !t.endsWith(OTEL_TOKEN_SCOPE_SUFFIX)),
  );
}

/**
 * Token check for the OTLP receiver: accepts full tokens and
 * `@otel`-scoped tokens (matched after stripping the suffix from the
 * configured entry). App teams hold scoped tokens, so a leaked app token
 * cannot write collector events or read fleet coverage.
 */
export function isValidOtelToken(candidate: string, allowedTokens: string[]): boolean {
  return matchesAny(
    candidate,
    allowedTokens.map((t) =>
      t.endsWith(OTEL_TOKEN_SCOPE_SUFFIX) ? t.slice(0, -OTEL_TOKEN_SCOPE_SUFFIX.length) : t,
    ),
  );
}

/** Extract a bearer token from an Authorization header, or null. */
export function bearerToken(authorizationHeader: string | undefined): string | null {
  if (!authorizationHeader) return null;
  const [scheme, ...rest] = authorizationHeader.split(" ");
  if (scheme?.toLowerCase() !== "bearer" || rest.length !== 1) return null;
  const token = rest[0];
  return token && token.length > 0 ? token : null;
}
