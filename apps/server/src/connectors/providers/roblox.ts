import { createOAuth2Connector } from "../oauth2Connector.js";
import type { UpstreamConnector } from "../types.js";

// Confirmed as real OAuth2 + mandatory PKCE (S256) by auditing
// SocialLinkUpOnly's own working auth/roblox.js — see TODO.md Phase 4.
export function createRobloxConnector(clientId: string, clientSecret: string): UpstreamConnector {
  return createOAuth2Connector({
    id: "roblox",
    clientId,
    clientSecret,
    authorizationEndpoint: "https://apis.roblox.com/oauth/v1/authorize",
    tokenEndpoint: "https://apis.roblox.com/oauth/v1/token",
    userInfoEndpoint: "https://apis.roblox.com/oauth/v1/userinfo",
    scope: "openid profile",
    pkce: "required",
    tokenAuthMethod: "client_secret_post",
    mapUserInfo: (raw) => {
      const claims = raw as { sub: string; preferred_username?: string };
      return { id: claims.sub, username: claims.preferred_username, raw };
    },
  });
}
