import type { ConnectorPreset } from "../presets.js";

// Confirmed as real OAuth2 (no PKCE) by auditing SocialLinkUpOnly's own
// working auth/discord.js — see TODO.md Phase 4.
export const discordPreset: ConnectorPreset = {
  id: "discord",
  displayName: "Discord",
  type: "oauth2",
  authorizationEndpoint: "https://discord.com/oauth2/authorize",
  tokenEndpoint: "https://discord.com/api/oauth2/token",
  userInfoEndpoint: "https://discord.com/api/users/@me",
  scope: "identify email",
  // Discord's docs describe optional PKCE support; SocialLinkUpOnly's real
  // integration doesn't use it. Not re-confirmed live against Discord's
  // API in this session — optional is the safe default either way.
  pkce: "optional",
  tokenAuthMethod: "client_secret_post",
  mapUserInfo: (raw) => {
    const user = raw as { id: string; username: string; email?: string };
    return { id: user.id, username: user.username, email: user.email, raw };
  },
};
