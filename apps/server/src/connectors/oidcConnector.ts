import * as jose from "jose";
import { createOAuth2Connector } from "./oauth2Connector.js";
import type { UpstreamConnector, UpstreamUserInfo } from "./types.js";

export interface OidcConnectorConfig {
  id: string;
  issuer: string;
  clientId: string;
  clientSecret?: string;
  scope: string;
  pkce: "required" | "optional" | "unsupported";
  mapUserInfo: (claims: Record<string, unknown>) => UpstreamUserInfo;
}

interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
}

/**
 * A generic OIDC connector built on top of the generic OAuth 2.0 connector:
 * fetches the provider's discovery document instead of hardcoding endpoints,
 * and validates the id_token's signature/issuer/audience against the
 * provider's real JWKS before trusting anything in it. This is intentionally
 * not just "OAuth2 plus decode the JWT" — an unverified id_token is worthless
 * as proof of identity.
 */
export async function createOidcConnector(config: OidcConnectorConfig): Promise<UpstreamConnector> {
  // `config.issuer` only locates the discovery document — the value to
  // actually validate id_token `iss` against is the discovery document's OWN
  // `issuer` field, which is the spec-correct source of truth and can
  // legitimately differ from the URL used to fetch it (e.g. behind a proxy,
  // or — as found while testing this against our own server — when the
  // reachable host differs from the provider's statically configured
  // identity). Verifying against `config.issuer` instead was a real bug
  // caught by this connector's own test, not a hypothetical edge case.
  const discoveryUrl = config.issuer.replace(/\/$/, "");
  const discoveryRes = await fetch(`${discoveryUrl}/.well-known/openid-configuration`);
  if (!discoveryRes.ok) {
    throw new Error(`${config.id}: failed to fetch OIDC discovery document (${discoveryRes.status})`);
  }
  const discovery = (await discoveryRes.json()) as OidcDiscoveryDocument;

  const jwks = jose.createRemoteJWKSet(new URL(discovery.jwks_uri));

  const oauth2 = createOAuth2Connector({
    id: config.id,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    authorizationEndpoint: discovery.authorization_endpoint,
    tokenEndpoint: discovery.token_endpoint,
    userInfoEndpoint: discovery.userinfo_endpoint,
    scope: config.scope,
    pkce: config.pkce,
    mapUserInfo: (raw) => config.mapUserInfo(raw as Record<string, unknown>),
  });

  return {
    ...oauth2,
    async exchangeCode(params) {
      const tokens = await oauth2.exchangeCode(params);
      if (!tokens.idToken) {
        throw new Error(`${config.id}: token response had no id_token — not a real OIDC provider response`);
      }

      // Throws on bad signature, wrong issuer, or wrong audience — this is
      // the check that actually makes the id_token trustworthy.
      await jose.jwtVerify(tokens.idToken, jwks, {
        issuer: discovery.issuer,
        audience: config.clientId,
      });

      return tokens;
    },
  };
}
