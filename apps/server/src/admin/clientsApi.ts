import crypto from "node:crypto";
import { Router } from "express";
import { recordAuditEvent } from "../audit/log.js";
import { prisma } from "../db.js";
import { requirePermission, type RequestWithAdmin } from "../rbac/requirePermission.js";
import { encryptSecret } from "../security/encryption.js";

/**
 * Real CRUD for registering downstream Neko* projects as OAuth2 Clients —
 * previously only possible by hand-editing the database via Prisma seed
 * scripts. This is the backend half of Phase 8's console "manage clients"
 * screen (`apps/console`). Gated by `admin:manage_clients`, same
 * requirePermission mechanism as every other admin API in this repo.
 */
export const clientsApiRouter = Router();
clientsApiRouter.use(requirePermission("admin:manage_clients"));

function serializeClient(client: {
  id: string;
  tenantId: string;
  name: string;
  clientId: string;
  clientSecret: string | null;
  isConfidential: boolean;
  redirectUris: string[];
  grantTypes: string[];
  responseTypes: string[];
  scope: string;
  tokenEndpointAuthMethod: string;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: client.id,
    tenantId: client.tenantId,
    name: client.name,
    clientId: client.clientId,
    isConfidential: client.isConfidential,
    redirectUris: client.redirectUris,
    grantTypes: client.grantTypes,
    responseTypes: client.responseTypes,
    scope: client.scope,
    tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
    createdAt: client.createdAt,
    updatedAt: client.updatedAt,
    // Never the raw secret — only whether one is set, same pattern as
    // src/email/smtpConfigApi.ts's `hasPassword`.
    hasSecret: Boolean(client.clientSecret),
  };
}

async function defaultTenant() {
  return prisma.tenant.upsert({
    where: { slug: "neko" },
    update: {},
    create: { name: "Neko", slug: "neko" },
  });
}

function generateClientId(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
  const suffix = crypto.randomBytes(4).toString("hex");
  return slug ? `${slug}-${suffix}` : suffix;
}

function generateClientSecret(): string {
  return crypto.randomBytes(32).toString("base64url");
}

clientsApiRouter.get("/", async (_req, res) => {
  const clients = await prisma.client.findMany({ orderBy: { createdAt: "desc" } });
  res.json(clients.map(serializeClient));
});

clientsApiRouter.get("/:id", async (req, res) => {
  const client = await prisma.client.findUnique({ where: { id: req.params.id } });
  if (!client) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  res.json(serializeClient(client));
});

clientsApiRouter.post("/", async (req, res) => {
  const body = req.body as {
    name?: unknown;
    redirectUris?: unknown;
    scope?: unknown;
    isConfidential?: unknown;
    tokenEndpointAuthMethod?: unknown;
    grantTypes?: unknown;
    responseTypes?: unknown;
  };

  if (typeof body.name !== "string" || !body.name.trim()) {
    res.status(400).json({ error: "invalid_body", error_description: "name is required" });
    return;
  }
  const redirectUris = Array.isArray(body.redirectUris) ? body.redirectUris.filter((u) => typeof u === "string") : [];
  if (redirectUris.length === 0) {
    res.status(400).json({ error: "invalid_body", error_description: "at least one redirect URI is required" });
    return;
  }

  const isConfidential = typeof body.isConfidential === "boolean" ? body.isConfidential : true;
  const tokenEndpointAuthMethod =
    typeof body.tokenEndpointAuthMethod === "string"
      ? body.tokenEndpointAuthMethod
      : isConfidential
        ? "client_secret_basic"
        : "none";

  const tenant = await defaultTenant();
  const clientId = generateClientId(body.name);
  const clientSecret = isConfidential && tokenEndpointAuthMethod !== "none" ? generateClientSecret() : null;

  const client = await prisma.client.create({
    data: {
      tenantId: tenant.id,
      name: body.name,
      clientId,
      clientSecret: clientSecret ? encryptSecret(clientSecret) : null,
      isConfidential,
      redirectUris,
      scope: typeof body.scope === "string" ? body.scope : "openid profile email",
      grantTypes: Array.isArray(body.grantTypes)
        ? body.grantTypes.filter((g) => typeof g === "string")
        : ["authorization_code", "refresh_token"],
      responseTypes: Array.isArray(body.responseTypes)
        ? body.responseTypes.filter((r) => typeof r === "string")
        : ["code"],
      tokenEndpointAuthMethod,
    },
  });

  void recordAuditEvent("admin.client.created", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "Client",
    targetId: client.id,
    metadata: { name: client.name, clientId: client.clientId },
  });

  // The only time the raw secret is ever returned — the admin must copy it
  // now, same "shown once" pattern as the rotate-secret endpoint below.
  res.status(201).json({ ...serializeClient(client), clientSecret });
});

clientsApiRouter.patch("/:id", async (req, res) => {
  const existing = await prisma.client.findUnique({ where: { id: req.params.id } });
  if (!existing) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  const body = req.body as {
    name?: unknown;
    redirectUris?: unknown;
    scope?: unknown;
    isConfidential?: unknown;
    tokenEndpointAuthMethod?: unknown;
    grantTypes?: unknown;
    responseTypes?: unknown;
  };

  const data: Record<string, unknown> = {};
  if (typeof body.name === "string" && body.name.trim()) data.name = body.name;
  if (Array.isArray(body.redirectUris)) {
    const redirectUris = body.redirectUris.filter((u) => typeof u === "string");
    if (redirectUris.length === 0) {
      res.status(400).json({ error: "invalid_body", error_description: "at least one redirect URI is required" });
      return;
    }
    data.redirectUris = redirectUris;
  }
  if (typeof body.scope === "string") data.scope = body.scope;
  if (typeof body.isConfidential === "boolean") data.isConfidential = body.isConfidential;
  if (typeof body.tokenEndpointAuthMethod === "string") data.tokenEndpointAuthMethod = body.tokenEndpointAuthMethod;
  if (Array.isArray(body.grantTypes)) data.grantTypes = body.grantTypes.filter((g) => typeof g === "string");
  if (Array.isArray(body.responseTypes)) data.responseTypes = body.responseTypes.filter((r) => typeof r === "string");

  const client = await prisma.client.update({ where: { id: req.params.id }, data });

  void recordAuditEvent("admin.client.updated", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "Client",
    targetId: client.id,
    metadata: { changedFields: Object.keys(data) },
  });

  res.json(serializeClient(client));
});

clientsApiRouter.post("/:id/rotate-secret", async (req, res) => {
  const existing = await prisma.client.findUnique({ where: { id: req.params.id } });
  if (!existing) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  if (!existing.isConfidential || existing.tokenEndpointAuthMethod === "none") {
    res.status(400).json({
      error: "invalid_request",
      error_description: "only confidential clients with a secret-based auth method have a secret to rotate",
    });
    return;
  }

  const clientSecret = generateClientSecret();
  const client = await prisma.client.update({
    where: { id: req.params.id },
    data: { clientSecret: encryptSecret(clientSecret) },
  });

  void recordAuditEvent("admin.client.secret_rotated", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "Client",
    targetId: client.id,
  });

  res.json({ ...serializeClient(client), clientSecret });
});
