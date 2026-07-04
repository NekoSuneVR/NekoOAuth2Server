import { Router } from "express";
import { recordAuditEvent } from "../audit/log.js";
import { prisma } from "../db.js";
import { requirePermission, type RequestWithAdmin } from "../rbac/requirePermission.js";
import { encryptSecret } from "../security/encryption.js";
import { SMTP_CONFIG_ID } from "./senderProvider.js";

export const smtpConfigRouter = Router();
smtpConfigRouter.use(requirePermission("email:manage_smtp"));

function redact(config: {
  id: string;
  host: string;
  port: number;
  secure: boolean;
  username: string | null;
  password: string | null;
  fromAddress: string;
  fromName: string | null;
  updatedAt: Date;
}) {
  return {
    host: config.host,
    port: config.port,
    secure: config.secure,
    username: config.username,
    fromAddress: config.fromAddress,
    fromName: config.fromName,
    updatedAt: config.updatedAt,
    // Never echo the password back — only whether one is set.
    hasPassword: Boolean(config.password),
  };
}

smtpConfigRouter.get("/", async (_req, res) => {
  const config = await prisma.smtpConfig.findUnique({ where: { id: SMTP_CONFIG_ID } });
  if (!config) {
    res.status(404).json({ error: "not_configured" });
    return;
  }
  res.json(redact(config));
});

smtpConfigRouter.put("/", async (req, res) => {
  const body = req.body as {
    host?: unknown;
    port?: unknown;
    secure?: unknown;
    username?: unknown;
    password?: unknown;
    fromAddress?: unknown;
    fromName?: unknown;
  };

  if (typeof body.host !== "string" || typeof body.port !== "number" || typeof body.fromAddress !== "string") {
    res.status(400).json({ error: "invalid_body", error_description: "host, port, and fromAddress are required" });
    return;
  }

  const data = {
    host: body.host,
    port: body.port,
    secure: typeof body.secure === "boolean" ? body.secure : false,
    username: typeof body.username === "string" ? body.username : null,
    fromAddress: body.fromAddress,
    fromName: typeof body.fromName === "string" ? body.fromName : null,
    // Only overwritten when a new password is actually sent — a PUT that
    // just changes the host shouldn't silently wipe a previously set secret.
    // Encrypted at rest (Phase 9) — see src/security/encryption.ts.
    ...(typeof body.password === "string" ? { password: encryptSecret(body.password) } : {}),
  };

  const config = await prisma.smtpConfig.upsert({
    where: { id: SMTP_CONFIG_ID },
    update: data,
    create: { id: SMTP_CONFIG_ID, password: null, ...data },
  });

  void recordAuditEvent("admin.smtp_config.updated", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "SmtpConfig",
    targetId: SMTP_CONFIG_ID,
  });

  res.json(redact(config));
});
