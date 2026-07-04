import type { ConnectorPreset } from "../presets.js";

// Authorize/token endpoints and mandatory PKCE (S256) are exactly as given
// (see TODO.md Phase 4). The userinfo endpoint is NOT explicitly specified —
// VPZone's own flow description only mentions calling `/api/v1/*` generically
// with the bearer token, not a specific "who am I" endpoint. `/api/v1/me` is
// assumed by convention; confirm against VPZone's real API docs before this
// connector is used for anything real.
export const vpzonePreset: ConnectorPreset = {
  id: "vpzone",
  displayName: "VPZone",
  type: "oauth2",
  authorizationEndpoint: "https://vpzone.tv/oauth/authorize",
  tokenEndpoint: "https://vpzone.tv/api/oauth/token",
  userInfoEndpoint: "https://vpzone.tv/api/v1/me",
  scope: "identify",
  pkce: "required",
  tokenAuthMethod: "client_secret_post",
  mapUserInfo: (raw) => {
    const user = raw as { id: string | number; username?: string };
    return { id: String(user.id), username: user.username, raw };
  },
};
