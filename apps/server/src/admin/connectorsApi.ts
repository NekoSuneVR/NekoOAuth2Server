import { Router } from "express";
import { recordAuditEvent } from "../audit/log.js";
import { buildConnectorFromRow, loadConnectorRegistryFromDb } from "../connectors/registry.js";
import { CONNECTOR_PRESETS } from "../connectors/presets.js";
import { prisma } from "../db.js";
import { requirePermission, type RequestWithAdmin } from "../rbac/requirePermission.js";
import { encryptSecret } from "../security/encryption.js";

/**
 * Admin CRUD for upstream connectors (TODO.md Phase 8/9) — the backend half
 * of the console's "grid of provider cards + customize by standard
 * protocol" screen. Every mutation reloads the live in-memory registry
 * (src/connectors/registry.ts) immediately, so a change here takes effect
 * without restarting the server — the actual point of moving connector
 * config off env vars and into the database.
 */
export const connectorsApiRouter = Router();
connectorsApiRouter.use(requirePermission("admin:manage_connectors"));

function serializeConnector(row: {
  id: string;
  providerId: string;
  displayName: string;
  presetId: string | null;
  type: string;
  clientId: string;
  authorizationEndpoint: string | null;
  tokenEndpoint: string | null;
  userInfoEndpoint: string | null;
  issuer: string | null;
  scope: string;
  pkce: string;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: row.id,
    providerId: row.providerId,
    displayName: row.displayName,
    presetId: row.presetId,
    type: row.type,
    clientId: row.clientId,
    authorizationEndpoint: row.authorizationEndpoint,
    tokenEndpoint: row.tokenEndpoint,
    userInfoEndpoint: row.userInfoEndpoint,
    issuer: row.issuer,
    scope: row.scope,
    pkce: row.pkce,
    enabled: row.enabled,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

connectorsApiRouter.get("/presets", (_req, res) => {
  res.json(
    Object.values(CONNECTOR_PRESETS).map((preset) => ({
      id: preset.id,
      displayName: preset.displayName,
      type: preset.type,
      scope: preset.scope,
      pkce: preset.pkce,
    })),
  );
});

connectorsApiRouter.get("/", async (_req, res) => {
  const rows = await prisma.connector.findMany({ orderBy: { createdAt: "desc" } });
  res.json(rows.map(serializeConnector));
});

connectorsApiRouter.get("/:id", async (req, res) => {
  const row = await prisma.connector.findUnique({ where: { id: req.params.id } });
  if (!row) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  res.json(serializeConnector(row));
});

connectorsApiRouter.post("/", async (req, res) => {
  const body = req.body as {
    providerId?: unknown;
    displayName?: unknown;
    presetId?: unknown;
    type?: unknown;
    clientId?: unknown;
    clientSecret?: unknown;
    scope?: unknown;
    pkce?: unknown;
    authorizationEndpoint?: unknown;
    tokenEndpoint?: unknown;
    userInfoEndpoint?: unknown;
    issuer?: unknown;
  };

  if (typeof body.clientId !== "string" || typeof body.clientSecret !== "string") {
    res.status(400).json({ error: "invalid_body", error_description: "clientId and clientSecret are required" });
    return;
  }

  const preset = typeof body.presetId === "string" ? CONNECTOR_PRESETS[body.presetId] : undefined;
  if (typeof body.presetId === "string" && !preset) {
    res.status(400).json({ error: "invalid_body", error_description: `unknown presetId "${body.presetId}"` });
    return;
  }

  const providerId = typeof body.providerId === "string" && body.providerId ? body.providerId : preset?.id;
  if (!providerId) {
    res.status(400).json({ error: "invalid_body", error_description: "providerId is required for a custom connector" });
    return;
  }

  const existing = await prisma.connector.findUnique({ where: { providerId } });
  if (existing) {
    res.status(409).json({ error: "already_exists", error_description: `a connector with providerId "${providerId}" already exists` });
    return;
  }

  const type = preset?.type ?? (body.type === "oidc" ? "oidc" : "oauth2");
  const data = {
    providerId,
    displayName: preset?.displayName ?? (typeof body.displayName === "string" ? body.displayName : providerId),
    presetId: preset?.id ?? null,
    type,
    clientId: body.clientId,
    clientSecret: encryptSecret(body.clientSecret),
    authorizationEndpoint: typeof body.authorizationEndpoint === "string" ? body.authorizationEndpoint : null,
    tokenEndpoint: typeof body.tokenEndpoint === "string" ? body.tokenEndpoint : null,
    userInfoEndpoint: typeof body.userInfoEndpoint === "string" ? body.userInfoEndpoint : null,
    issuer: typeof body.issuer === "string" ? body.issuer : null,
    scope: preset?.scope ?? (typeof body.scope === "string" ? body.scope : "openid profile email"),
    pkce: preset?.pkce ?? (typeof body.pkce === "string" ? body.pkce : "required"),
    enabled: true,
  };

  // Prove the connector actually builds (real discovery fetch for OIDC,
  // required-field checks for custom OAuth2) before persisting it — a
  // silent failure would just make this provider quietly never appear as a
  // login option, with no feedback to the admin who configured it.
  try {
    await buildConnectorFromRow(data);
  } catch (err) {
    res.status(400).json({
      error: "invalid_connector_config",
      error_description: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  const row = await prisma.connector.create({ data });
  await loadConnectorRegistryFromDb();

  void recordAuditEvent("admin.connector.created", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "Connector",
    targetId: row.id,
    metadata: { providerId: row.providerId, presetId: row.presetId },
  });

  res.status(201).json(serializeConnector(row));
});

connectorsApiRouter.patch("/:id", async (req, res) => {
  const existing = await prisma.connector.findUnique({ where: { id: req.params.id } });
  if (!existing) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  const body = req.body as {
    displayName?: unknown;
    clientId?: unknown;
    clientSecret?: unknown;
    scope?: unknown;
    pkce?: unknown;
    authorizationEndpoint?: unknown;
    tokenEndpoint?: unknown;
    userInfoEndpoint?: unknown;
    issuer?: unknown;
    enabled?: unknown;
  };

  const data: Record<string, unknown> = {};
  if (typeof body.displayName === "string") data.displayName = body.displayName;
  if (typeof body.clientId === "string") data.clientId = body.clientId;
  if (typeof body.clientSecret === "string") data.clientSecret = encryptSecret(body.clientSecret);
  if (typeof body.scope === "string") data.scope = body.scope;
  if (typeof body.pkce === "string") data.pkce = body.pkce;
  if (typeof body.authorizationEndpoint === "string") data.authorizationEndpoint = body.authorizationEndpoint;
  if (typeof body.tokenEndpoint === "string") data.tokenEndpoint = body.tokenEndpoint;
  if (typeof body.userInfoEndpoint === "string") data.userInfoEndpoint = body.userInfoEndpoint;
  if (typeof body.issuer === "string") data.issuer = body.issuer;
  if (typeof body.enabled === "boolean") data.enabled = body.enabled;

  const merged = { ...existing, ...data };
  if (merged.enabled) {
    try {
      await buildConnectorFromRow(merged);
    } catch (err) {
      res.status(400).json({
        error: "invalid_connector_config",
        error_description: err instanceof Error ? err.message : String(err),
      });
      return;
    }
  }

  const row = await prisma.connector.update({ where: { id: req.params.id }, data });
  await loadConnectorRegistryFromDb();

  void recordAuditEvent("admin.connector.updated", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "Connector",
    targetId: row.id,
    metadata: { changedFields: Object.keys(data) },
  });

  res.json(serializeConnector(row));
});

connectorsApiRouter.delete("/:id", async (req, res) => {
  const existing = await prisma.connector.findUnique({ where: { id: req.params.id } });
  if (!existing) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  await prisma.connector.delete({ where: { id: req.params.id } });
  await loadConnectorRegistryFromDb();

  void recordAuditEvent("admin.connector.deleted", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "Connector",
    targetId: req.params.id,
    metadata: { providerId: existing.providerId },
  });

  res.status(204).send();
});
