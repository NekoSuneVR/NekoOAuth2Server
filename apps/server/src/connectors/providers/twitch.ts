import type { ConnectorPreset } from "../presets.js";

// Confirmed as real OAuth2 by auditing SocialLinkUpOnly's own working
// auth/twitch.js — see TODO.md Phase 4. Twitch's Helix API (unlike the
// authorize/token endpoints) requires a Client-Id header on every call,
// not just the standard Bearer token.
export const twitchPreset: ConnectorPreset = {
  id: "twitch",
  displayName: "Twitch",
  type: "oauth2",
  authorizationEndpoint: "https://id.twitch.tv/oauth2/authorize",
  tokenEndpoint: "https://id.twitch.tv/oauth2/token",
  userInfoEndpoint: "https://api.twitch.tv/helix/users",
  scope: "user:read:email",
  // Twitch's docs describe optional PKCE support; not re-confirmed live
  // against Twitch's API in this session.
  pkce: "optional",
  tokenAuthMethod: "client_secret_post",
  userInfoHeaders: (clientId) => ({ "Client-Id": clientId }),
  mapUserInfo: (raw) => {
    const body = raw as { data: Array<{ id: string; login: string; email?: string }> };
    const user = body.data[0];
    if (!user) throw new Error("twitch: userinfo response had no user");
    return { id: user.id, username: user.login, email: user.email, raw };
  },
};
