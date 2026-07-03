import crypto from "node:crypto";

/**
 * The server requires PKCE from every client, confidential or not (see the
 * server repo's TODO.md Phase 1) — so unlike the server's own upstream
 * connectors, which have to tolerate providers that don't support PKCE at
 * all, this SDK always generates and sends it. There's no tri-state here.
 */
export function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString("base64url");
}

export function generateCodeChallenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

export function generateState(): string {
  return crypto.randomBytes(16).toString("base64url");
}
