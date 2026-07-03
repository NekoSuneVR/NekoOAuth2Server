import crypto from "node:crypto";

/**
 * Generates a code_verifier/code_challenge pair for connectors that use
 * PKCE. The caller (our own interaction routes) owns persisting the verifier
 * between the redirect-out and redirect-back — the connector itself is
 * stateless.
 */
export function generatePkcePair() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}
