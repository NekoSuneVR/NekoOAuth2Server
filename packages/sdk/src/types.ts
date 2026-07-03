export interface NekoAuthConfig {
  /** e.g. "https://oauth2.nekosunevr.co.uk/oidc" — the OIDC issuer, not the bare host. */
  issuer: string;
  clientId: string;
  /** Only for confidential clients (see the server's tokenEndpointAuthMethod for that client). */
  clientSecret?: string;
  redirectUri: string;
  /** Defaults to "openid profile email". */
  scope?: string;
}

export interface TokenSet {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresIn?: number;
  tokenType: string;
  scope?: string;
}

export interface IdTokenClaims {
  sub: string;
  [claim: string]: unknown;
}

export interface UserProfile {
  sub: string;
  name?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
  roles?: string[];
  permissions?: string[];
  [claim: string]: unknown;
}
