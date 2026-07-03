import * as jose from "jose";
import { fetchDiscoveryDocument, type DiscoveryDocument } from "./discovery.js";
import { generateCodeChallenge, generateCodeVerifier, generateState } from "./pkce.js";
import type { IdTokenClaims, NekoAuthConfig, TokenSet, UserProfile } from "./types.js";

export interface AuthorizationRequest {
  url: string;
  state: string;
  codeVerifier: string;
}

interface TokenResponseBody {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type: string;
  scope?: string;
  error?: string;
  error_description?: string;
}

function mapTokenResponse(body: TokenResponseBody): TokenSet {
  return {
    accessToken: body.access_token,
    idToken: body.id_token,
    refreshToken: body.refresh_token,
    expiresIn: body.expires_in,
    tokenType: body.token_type,
    scope: body.scope,
  };
}

/**
 * A thin OIDC relying-party client for NekoOAuth2Server. Framework-agnostic —
 * see express.ts for the Express-specific login/callback/session wiring on
 * top of this.
 */
export class NekoAuthClient {
  #config: NekoAuthConfig & { scope: string };
  #discovery?: DiscoveryDocument;
  #jwks?: ReturnType<typeof jose.createRemoteJWKSet>;

  constructor(config: NekoAuthConfig) {
    this.#config = { scope: "openid profile email", ...config };
  }

  async #ensureDiscovery(): Promise<DiscoveryDocument> {
    if (!this.#discovery) {
      this.#discovery = await fetchDiscoveryDocument(this.#config.issuer);
      this.#jwks = jose.createRemoteJWKSet(new URL(this.#discovery.jwks_uri));
    }
    return this.#discovery;
  }

  /** Builds the authorize redirect URL and the PKCE/state values the caller must persist until the callback. */
  async createAuthorizationRequest(options?: {
    scope?: string;
    extraParams?: Record<string, string>;
  }): Promise<AuthorizationRequest> {
    const discovery = await this.#ensureDiscovery();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const state = generateState();

    const url = new URL(discovery.authorization_endpoint);
    url.searchParams.set("client_id", this.#config.clientId);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("redirect_uri", this.#config.redirectUri);
    url.searchParams.set("scope", options?.scope ?? this.#config.scope);
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    for (const [key, value] of Object.entries(options?.extraParams ?? {})) {
      url.searchParams.set(key, value);
    }

    return { url: url.toString(), state, codeVerifier };
  }

  async exchangeCode(params: { code: string; codeVerifier: string }): Promise<TokenSet> {
    const discovery = await this.#ensureDiscovery();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: params.code,
      redirect_uri: this.#config.redirectUri,
      client_id: this.#config.clientId,
      code_verifier: params.codeVerifier,
    });

    const res = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: this.#tokenRequestHeaders(),
      body,
    });
    const json = (await res.json()) as TokenResponseBody;
    if (!res.ok) {
      throw new Error(`token exchange failed: ${json.error ?? res.status} ${json.error_description ?? ""}`.trim());
    }
    return mapTokenResponse(json);
  }

  async refreshToken(refreshToken: string): Promise<TokenSet> {
    const discovery = await this.#ensureDiscovery();
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.#config.clientId,
    });

    const res = await fetch(discovery.token_endpoint, {
      method: "POST",
      headers: this.#tokenRequestHeaders(),
      body,
    });
    const json = (await res.json()) as TokenResponseBody;
    if (!res.ok) {
      throw new Error(`token refresh failed: ${json.error ?? res.status} ${json.error_description ?? ""}`.trim());
    }
    return mapTokenResponse(json);
  }

  #tokenRequestHeaders(): Record<string, string> {
    const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded" };
    if (this.#config.clientSecret) {
      const basic = Buffer.from(`${this.#config.clientId}:${this.#config.clientSecret}`).toString("base64");
      headers.Authorization = `Basic ${basic}`;
    }
    return headers;
  }

  /** Verifies signature, issuer, and audience against the server's real JWKS — never trust an unverified id_token. */
  async verifyIdToken(idToken: string): Promise<IdTokenClaims> {
    await this.#ensureDiscovery();
    const { payload } = await jose.jwtVerify(idToken, this.#jwks!, {
      issuer: this.#discovery!.issuer,
      audience: this.#config.clientId,
    });
    return payload as IdTokenClaims;
  }

  async getUserInfo(accessToken: string): Promise<UserProfile> {
    const discovery = await this.#ensureDiscovery();
    const res = await fetch(discovery.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) {
      throw new Error(`userinfo request failed (${res.status})`);
    }
    return (await res.json()) as UserProfile;
  }
}

export function createNekoAuthClient(config: NekoAuthConfig): NekoAuthClient {
  return new NekoAuthClient(config);
}
