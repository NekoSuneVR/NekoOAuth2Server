import { prisma } from "../db.js";
import { decryptSecret, encryptSecret, isEncryptedSecret } from "../security/encryption.js";
import { createOAuth2Connector } from "./oauth2Connector.js";
import { createOidcConnector } from "./oidcConnector.js";
import { CONNECTOR_PRESETS, defaultMapUserInfo } from "./presets.js";
import type { UpstreamConnector } from "./types.js";

/**
 * Exactly the fields buildConnectorFromRow actually reads — narrower than
 * the full Prisma `Connector` row so the admin API (src/admin/connectorsApi.ts)
 * can validate a connector config *before* it has a real id/createdAt/
 * updatedAt (i.e. before the row is persisted), without an `as` cast to
 * paper over the missing fields.
 */
export interface ConnectorBuildInput {
  providerId: string;
  presetId: string | null;
  type: string;
  clientId: string;
  clientSecret: string;
  authorizationEndpoint: string | null;
  tokenEndpoint: string | null;
  userInfoEndpoint: string | null;
  issuer: string | null;
  scope: string;
  pkce: string;
}

/**
 * Live, in-memory connector registry — a plain mutable Map, same reference
 * for the process's whole lifetime, so every route that already does
 * `connectorRegistry.get(...)`/`.keys()` keeps working unchanged regardless
 * of *how* it got populated. Empty by default; real deployments populate it
 * via `loadConnectorRegistryFromDb()` (called once at startup and again
 * after any admin mutation — see src/admin/connectorsApi.ts), tests
 * populate it directly via `registerConnector()`.
 */
export const connectorRegistry = new Map<string, UpstreamConnector>();

/** Test-only escape hatch for registering a mock connector without a real DB row. */
export function registerConnector(id: string, connector: UpstreamConnector) {
  connectorRegistry.set(id, connector);
}

function resolveSecret(stored: string): string {
  return isEncryptedSecret(stored) ? decryptSecret(stored) : stored;
}

export async function buildConnectorFromRow(row: ConnectorBuildInput): Promise<UpstreamConnector> {
  const clientSecret = resolveSecret(row.clientSecret);
  const preset = row.presetId ? CONNECTOR_PRESETS[row.presetId] : undefined;

  if (row.type === "oidc") {
    const issuer = preset?.issuer ?? row.issuer;
    if (!issuer) throw new Error(`connector "${row.providerId}": oidc type requires an issuer`);
    return createOidcConnector({
      id: row.providerId,
      issuer,
      clientId: row.clientId,
      clientSecret,
      scope: row.scope,
      pkce: (row.pkce as "required" | "optional" | "unsupported") ?? "required",
      mapUserInfo: preset?.mapUserInfo ?? defaultMapUserInfo,
    });
  }

  if (preset) {
    return createOAuth2Connector({
      id: row.providerId,
      clientId: row.clientId,
      clientSecret,
      authorizationEndpoint: preset.authorizationEndpoint!,
      tokenEndpoint: preset.tokenEndpoint!,
      userInfoEndpoint: preset.userInfoEndpoint!,
      scope: row.scope || preset.scope,
      pkce: (row.pkce as "required" | "optional" | "unsupported") ?? preset.pkce,
      tokenAuthMethod: preset.tokenAuthMethod,
      userInfoHeaders: preset.userInfoHeaders ? () => preset.userInfoHeaders!(row.clientId) : undefined,
      mapUserInfo: preset.mapUserInfo,
    });
  }

  if (!row.authorizationEndpoint || !row.tokenEndpoint || !row.userInfoEndpoint) {
    throw new Error(`connector "${row.providerId}": custom oauth2 connectors need authorizationEndpoint/tokenEndpoint/userInfoEndpoint`);
  }
  return createOAuth2Connector({
    id: row.providerId,
    clientId: row.clientId,
    clientSecret,
    authorizationEndpoint: row.authorizationEndpoint,
    tokenEndpoint: row.tokenEndpoint,
    userInfoEndpoint: row.userInfoEndpoint,
    scope: row.scope,
    pkce: (row.pkce as "required" | "optional" | "unsupported") ?? "required",
    tokenAuthMethod: "client_secret_post",
    mapUserInfo: defaultMapUserInfo,
  });
}

/**
 * Rebuilds the live registry from the database — called once at server
 * startup and again after any admin create/update/delete/enable-toggle
 * (src/admin/connectorsApi.ts) so changes take effect without a restart.
 * A connector that fails to build (e.g. bad OIDC issuer) is skipped with a
 * logged error rather than taking down every other connector.
 */
export async function loadConnectorRegistryFromDb(): Promise<void> {
  const rows = await prisma.connector.findMany({ where: { enabled: true } });
  const next = new Map<string, UpstreamConnector>();

  for (const row of rows) {
    try {
      next.set(row.providerId, await buildConnectorFromRow(row));
    } catch (err) {
      console.error(`Failed to build connector "${row.providerId}":`, err);
    }
  }

  connectorRegistry.clear();
  for (const [id, connector] of next) connectorRegistry.set(id, connector);
}

const LEGACY_ENV_PRESET_IDS = ["discord", "roblox", "twitch", "vpzone"];

/**
 * One-time migration for deployments still using Phase 4's original
 * `${ID}_CLIENT_ID`/`${ID}_CLIENT_SECRET` env vars — runs only when the
 * Connector table is completely empty, so an existing deployment's
 * env-var-configured connectors survive the upgrade to DB-backed config
 * instead of silently disappearing. A fresh deployment with no env vars set
 * and no Connector rows just stays empty, same "disabled until configured"
 * pattern as everything else in this server.
 */
export async function migrateEnvConnectorsIfEmpty(): Promise<void> {
  const existingCount = await prisma.connector.count();
  if (existingCount > 0) return;

  for (const presetId of LEGACY_ENV_PRESET_IDS) {
    const clientId = process.env[`${presetId.toUpperCase()}_CLIENT_ID`];
    const clientSecret = process.env[`${presetId.toUpperCase()}_CLIENT_SECRET`];
    if (!clientId || !clientSecret) continue;

    const preset = CONNECTOR_PRESETS[presetId];
    await prisma.connector.create({
      data: {
        providerId: presetId,
        displayName: preset.displayName,
        presetId,
        type: preset.type,
        clientId,
        clientSecret: encryptSecret(clientSecret),
        scope: preset.scope,
        pkce: preset.pkce,
        enabled: true,
      },
    });
    console.log(`Migrated legacy ${presetId.toUpperCase()}_CLIENT_ID/SECRET env vars into a Connector row.`);
  }
}
