import crypto from "node:crypto";

// Packs the interaction uid + provider id + PKCE code_verifier into the
// OAuth2 `state` parameter itself (HMAC-signed), instead of needing a
// separate table to persist them across the redirect-out/redirect-back
// round trip to the upstream provider.
const STATE_SECRET = process.env.COOKIE_SECRET ?? "dev-insecure-cookie-secret-change-me";

// "login" drives the Phase 4 sign-in flow (tied to an in-progress OIDC
// interaction); "link" drives Phase 5's account-linking flow (tied to an
// already-authenticated account-portal session instead).
export type UpstreamState =
  | { mode: "login"; uid: string; provider: string; codeVerifier?: string }
  | { mode: "link"; userId: string; provider: string; codeVerifier?: string };

export function signUpstreamState(payload: UpstreamState): string {
  const json = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", STATE_SECRET).update(json).digest("base64url");
  return `${json}.${signature}`;
}

export function verifyUpstreamState(state: string): UpstreamState {
  const [json, signature] = state.split(".");
  if (!json || !signature) throw new Error("malformed upstream state");

  const expected = crypto.createHmac("sha256", STATE_SECRET).update(json).digest("base64url");
  const expectedBuf = Buffer.from(expected);
  const actualBuf = Buffer.from(signature);
  if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
    throw new Error("upstream state signature mismatch");
  }

  return JSON.parse(Buffer.from(json, "base64url").toString()) as UpstreamState;
}
