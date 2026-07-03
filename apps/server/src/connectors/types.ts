/**
 * Shared interface every upstream connector implements — standard OAuth2/OIDC
 * connectors (this file's consumers) and, eventually, non-standard ones like
 * VRChat's bot-verified flow (which does NOT implement this interface, since
 * it has no authorization redirect at all — see src/connectors/vrchat/).
 *
 * Mirrors the four-method shape Logto's own connector-kit uses (see TODO.md
 * Phase 0's research notes): getAuthorizationUri, authorizationCallbackHandler
 * (split here into exchangeCode + getUserInfo for clarity), getAccessToken.
 */
export interface UpstreamUserInfo {
  id: string;
  username?: string;
  email?: string;
  raw: unknown;
}

export interface UpstreamTokens {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  /** Present for OIDC connectors; validated (signature/issuer/audience) before this is ever set. */
  idToken?: string;
}

export interface UpstreamConnector {
  id: string;
  getAuthorizationUri(params: {
    state: string;
    redirectUri: string;
    codeVerifier?: string;
  }): string;
  exchangeCode(params: {
    code: string;
    redirectUri: string;
    codeVerifier?: string;
  }): Promise<UpstreamTokens>;
  getUserInfo(tokens: UpstreamTokens): Promise<UpstreamUserInfo>;
  /** "required" | "optional" | "unsupported" — see TODO.md Phase 4's note on why this can't be a single global assumption. */
  pkce: "required" | "optional" | "unsupported";
}
