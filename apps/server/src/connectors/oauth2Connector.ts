import crypto from "node:crypto";
import type { UpstreamConnector, UpstreamTokens, UpstreamUserInfo } from "./types.js";

export interface OAuth2ConnectorConfig {
  id: string;
  clientId: string;
  clientSecret?: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userInfoEndpoint: string;
  scope: string;
  // See TODO.md Phase 4: this varies per real-world provider and must never
  // be hardcoded as always-on or always-off.
  pkce: "required" | "optional" | "unsupported";
  // Some providers (e.g. Twitch's Helix API) need extra headers beyond
  // Authorization on the userinfo call.
  userInfoHeaders?: (accessToken: string) => Record<string, string>;
  // How the token endpoint expects client authentication.
  tokenAuthMethod?: "client_secret_post" | "client_secret_basic";
  mapUserInfo: (raw: unknown) => UpstreamUserInfo;
}

/**
 * A generic, config-driven OAuth 2.0 connector — the shape named providers
 * (Discord, Roblox, Twitch, VPZone, ...) are just pre-filled configs of, per
 * TODO.md Phase 0's connector-architecture decision. Implements the same
 * four-capability interface every connector (standard or bot-verified)
 * exposes.
 */
export function createOAuth2Connector(config: OAuth2ConnectorConfig): UpstreamConnector {
  function assertPkce(codeVerifier: string | undefined) {
    if (config.pkce === "required" && !codeVerifier) {
      throw new Error(`connector "${config.id}" requires PKCE but no code_verifier was supplied`);
    }
    if (config.pkce === "unsupported" && codeVerifier) {
      throw new Error(`connector "${config.id}" does not support PKCE but a code_verifier was supplied`);
    }
  }

  return {
    id: config.id,
    pkce: config.pkce,

    getAuthorizationUri({ state, redirectUri, codeVerifier }) {
      assertPkce(codeVerifier);

      const url = new URL(config.authorizationEndpoint);
      url.searchParams.set("response_type", "code");
      url.searchParams.set("client_id", config.clientId);
      url.searchParams.set("redirect_uri", redirectUri);
      url.searchParams.set("scope", config.scope);
      url.searchParams.set("state", state);

      if (config.pkce !== "unsupported" && codeVerifier) {
        // code_verifier itself is never sent here — only its SHA-256 hash.
        // Callers pass the *verifier*; connectors that want PKCE derive the
        // challenge themselves so it's always computed the same, correct way.
        const challenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
        url.searchParams.set("code_challenge", challenge);
        url.searchParams.set("code_challenge_method", "S256");
      }

      return url.toString();
    },

    async exchangeCode({ code, redirectUri, codeVerifier }) {
      assertPkce(codeVerifier);

      const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
      });
      if (config.pkce !== "unsupported" && codeVerifier) {
        body.set("code_verifier", codeVerifier);
      }

      const headers: Record<string, string> = {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      };

      if (config.tokenAuthMethod === "client_secret_basic" && config.clientSecret) {
        const basic = Buffer.from(`${config.clientId}:${config.clientSecret}`).toString("base64");
        headers.Authorization = `Basic ${basic}`;
      } else {
        body.set("client_id", config.clientId);
        if (config.clientSecret) body.set("client_secret", config.clientSecret);
      }

      const res = await fetch(config.tokenEndpoint, { method: "POST", headers, body });
      if (!res.ok) {
        throw new Error(`${config.id} token exchange failed: ${res.status} ${await res.text()}`);
      }

      const json = (await res.json()) as {
        access_token: string;
        refresh_token?: string;
        expires_in?: number;
        // Present for OIDC providers, unvalidated at this layer — the OIDC
        // connector wrapper (oidcConnector.ts) verifies signature/issuer/
        // audience before a caller ever sees this token.
        id_token?: string;
      };

      const tokens: UpstreamTokens = { accessToken: json.access_token };
      if (json.refresh_token) tokens.refreshToken = json.refresh_token;
      if (json.expires_in) tokens.expiresIn = json.expires_in;
      if (json.id_token) tokens.idToken = json.id_token;
      return tokens;
    },

    async getUserInfo(tokens) {
      const headers: Record<string, string> = {
        Authorization: `Bearer ${tokens.accessToken}`,
        ...config.userInfoHeaders?.(tokens.accessToken),
      };
      const res = await fetch(config.userInfoEndpoint, { headers });
      if (!res.ok) {
        throw new Error(`${config.id} userinfo request failed: ${res.status} ${await res.text()}`);
      }
      const raw = await res.json();
      return config.mapUserInfo(raw);
    },
  };
}
