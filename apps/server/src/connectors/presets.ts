import type { UpstreamUserInfo } from "./types.js";

/**
 * A named preset's endpoint/scope/pkce shape — everything about a provider
 * except the per-deployment clientId/clientSecret, which now live in the
 * database (see src/connectors/registry.ts) instead of `${ID}_CLIENT_ID`/
 * `${ID}_CLIENT_SECRET` env vars (Phase 4's original approach). Matches
 * Logto's own "named preset of a generic connector type" pattern (TODO.md
 * Phase 0).
 */
export interface ConnectorPreset {
  id: string;
  displayName: string;
  type: "oauth2" | "oidc";
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userInfoEndpoint?: string;
  /** OIDC presets only — the issuer to fetch discovery from instead of using fixed endpoints. */
  issuer?: string;
  scope: string;
  pkce: "required" | "optional" | "unsupported";
  tokenAuthMethod?: "client_secret_post" | "client_secret_basic";
  userInfoHeaders?: (clientId: string) => Record<string, string>;
  mapUserInfo: (raw: unknown) => UpstreamUserInfo;
}

/**
 * The fallback userinfo mapping for a fully custom connector (no preset) —
 * assumes a reasonably standard-shaped flat JSON response (OIDC-ish `sub`/
 * `preferred_username`, or Discord-ish `id`/`username`). A provider that
 * doesn't fit this shape needs a real preset with its own `mapUserInfo`,
 * not the admin console's generic "custom protocol" path.
 */
export function defaultMapUserInfo(raw: unknown): UpstreamUserInfo {
  const obj = raw as Record<string, unknown>;
  const id = obj.sub ?? obj.id;
  if (typeof id !== "string" && typeof id !== "number") {
    throw new Error("custom connector userinfo response has no 'id' or 'sub' field");
  }
  const username =
    (typeof obj.preferred_username === "string" && obj.preferred_username) ||
    (typeof obj.username === "string" && obj.username) ||
    (typeof obj.name === "string" && obj.name) ||
    undefined;
  const email = typeof obj.email === "string" ? obj.email : undefined;
  return { id: String(id), username, email, raw };
}

// Imported after the interface above so the provider files can import the
// type back from here without a circular runtime dependency.
import { discordPreset } from "./providers/discord.js";
import { robloxPreset } from "./providers/roblox.js";
import { twitchPreset } from "./providers/twitch.js";
import { vpzonePreset } from "./providers/vpzone.js";

export const CONNECTOR_PRESETS: Record<string, ConnectorPreset> = {
  discord: discordPreset,
  roblox: robloxPreset,
  twitch: twitchPreset,
  vpzone: vpzonePreset,
};
