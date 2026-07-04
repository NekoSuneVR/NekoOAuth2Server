import crypto from "node:crypto";
import { Router } from "express";
import { recordAuditEvent } from "../audit/log.js";
import { prisma } from "../db.js";
import { requirePermission, type RequestWithAdmin } from "../rbac/requirePermission.js";
import { assertSafeWebhookUrl, UnsafeWebhookUrlError } from "../security/ssrfGuard.js";
import { deliverToEndpoint } from "../webhooks/deliver.js";

/**
 * Admin CRUD for webhook endpoints, plus the delivery log and a "resend"
 * action (TODO.md Phase 8/9) — previously WebhookEndpoint rows could only be
 * created directly via Prisma (tests/seed), with no admin-facing way to
 * register one, rotate its secret, or see what happened to a delivery.
 */
export const webhooksApiRouter = Router();
webhooksApiRouter.use(requirePermission("admin:manage_webhooks"));

function generateSecret(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function serializeEndpoint(endpoint: {
  id: string;
  clientId: string;
  url: string;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: endpoint.id,
    clientId: endpoint.clientId,
    url: endpoint.url,
    enabled: endpoint.enabled,
    createdAt: endpoint.createdAt,
    updatedAt: endpoint.updatedAt,
  };
}

webhooksApiRouter.get("/", async (_req, res) => {
  const endpoints = await prisma.webhookEndpoint.findMany({ orderBy: { createdAt: "desc" } });
  res.json(endpoints.map(serializeEndpoint));
});

webhooksApiRouter.get("/:id", async (req, res) => {
  const endpoint = await prisma.webhookEndpoint.findUnique({ where: { id: req.params.id } });
  if (!endpoint) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  res.json(serializeEndpoint(endpoint));
});

webhooksApiRouter.post("/", async (req, res) => {
  const body = req.body as { clientId?: unknown; url?: unknown };
  if (typeof body.clientId !== "string" || typeof body.url !== "string") {
    res.status(400).json({ error: "invalid_body", error_description: "clientId and url are required" });
    return;
  }

  const client = await prisma.client.findUnique({ where: { id: body.clientId } });
  if (!client) {
    res.status(400).json({ error: "invalid_body", error_description: "unknown clientId" });
    return;
  }

  try {
    await assertSafeWebhookUrl(body.url);
  } catch (err) {
    if (err instanceof UnsafeWebhookUrlError) {
      res.status(400).json({ error: "unsafe_url", error_description: err.message });
      return;
    }
    throw err;
  }

  const secret = generateSecret();
  const endpoint = await prisma.webhookEndpoint.create({
    data: { clientId: client.id, url: body.url, secret },
  });

  void recordAuditEvent("admin.webhook.created", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "WebhookEndpoint",
    targetId: endpoint.id,
    metadata: { url: endpoint.url, forClientId: client.clientId },
  });

  // The only time the raw secret is ever returned.
  res.status(201).json({ ...serializeEndpoint(endpoint), secret });
});

webhooksApiRouter.patch("/:id", async (req, res) => {
  const existing = await prisma.webhookEndpoint.findUnique({ where: { id: req.params.id } });
  if (!existing) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  const body = req.body as { url?: unknown; enabled?: unknown };
  const data: Record<string, unknown> = {};

  if (typeof body.url === "string") {
    try {
      await assertSafeWebhookUrl(body.url);
    } catch (err) {
      if (err instanceof UnsafeWebhookUrlError) {
        res.status(400).json({ error: "unsafe_url", error_description: err.message });
        return;
      }
      throw err;
    }
    data.url = body.url;
  }
  if (typeof body.enabled === "boolean") data.enabled = body.enabled;

  const endpoint = await prisma.webhookEndpoint.update({ where: { id: req.params.id }, data });

  void recordAuditEvent("admin.webhook.updated", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "WebhookEndpoint",
    targetId: endpoint.id,
    metadata: { changedFields: Object.keys(data) },
  });

  res.json(serializeEndpoint(endpoint));
});

webhooksApiRouter.post("/:id/rotate-secret", async (req, res) => {
  const existing = await prisma.webhookEndpoint.findUnique({ where: { id: req.params.id } });
  if (!existing) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  const secret = generateSecret();
  const endpoint = await prisma.webhookEndpoint.update({ where: { id: req.params.id }, data: { secret } });

  void recordAuditEvent("admin.webhook.secret_rotated", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "WebhookEndpoint",
    targetId: endpoint.id,
  });

  res.json({ ...serializeEndpoint(endpoint), secret });
});

webhooksApiRouter.delete("/:id", async (req, res) => {
  const existing = await prisma.webhookEndpoint.findUnique({ where: { id: req.params.id } });
  if (!existing) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  await prisma.webhookDelivery.deleteMany({ where: { webhookEndpointId: req.params.id } });
  await prisma.webhookEndpoint.delete({ where: { id: req.params.id } });

  void recordAuditEvent("admin.webhook.deleted", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "WebhookEndpoint",
    targetId: req.params.id,
  });

  res.status(204).send();
});

webhooksApiRouter.get("/:id/deliveries", async (req, res) => {
  const endpoint = await prisma.webhookEndpoint.findUnique({ where: { id: req.params.id } });
  if (!endpoint) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  const deliveries = await prisma.webhookDelivery.findMany({
    where: { webhookEndpointId: req.params.id },
    orderBy: { deliveredAt: "desc" },
    take: 50,
  });
  res.json(deliveries);
});

webhooksApiRouter.post("/:id/deliveries/:deliveryId/resend", async (req, res) => {
  const endpoint = await prisma.webhookEndpoint.findUnique({ where: { id: req.params.id } });
  if (!endpoint) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  const delivery = await prisma.webhookDelivery.findUnique({ where: { id: req.params.deliveryId } });
  if (!delivery || delivery.webhookEndpointId !== endpoint.id) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  if (!delivery.payload || typeof delivery.payload !== "object") {
    res.status(400).json({
      error: "invalid_request",
      error_description: "this delivery has no stored payload to resend (predates payload logging)",
    });
    return;
  }

  const payload = delivery.payload as { event: string; data: unknown };
  await deliverToEndpoint(endpoint, payload.event, payload.data);

  void recordAuditEvent("admin.webhook.delivery_resent", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "WebhookEndpoint",
    targetId: endpoint.id,
    metadata: { originalDeliveryId: delivery.id, event: payload.event },
  });

  res.status(202).json({ ok: true });
});
