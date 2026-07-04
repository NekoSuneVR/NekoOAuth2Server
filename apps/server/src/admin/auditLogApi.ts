import { Router } from "express";
import { prisma } from "../db.js";
import { requirePermission } from "../rbac/requirePermission.js";

/**
 * Read-only — nothing ever writes to the audit log through this API, only
 * src/audit/log.ts's recordAuditEvent does. Gated by `admin:view_audit_log`
 * (deliberately its own permission, separate from any single admin
 * capability, so viewing the log can be granted without also granting the
 * ability to change anything it would record).
 */
export const auditLogApiRouter = Router();
auditLogApiRouter.use(requirePermission("admin:view_audit_log"));

const PAGE_SIZE = 50;

auditLogApiRouter.get("/", async (req, res) => {
  const event = typeof req.query.event === "string" ? req.query.event : undefined;
  const actorUserId = typeof req.query.actorUserId === "string" ? req.query.actorUserId : undefined;
  const targetType = typeof req.query.targetType === "string" ? req.query.targetType : undefined;
  const cursor = typeof req.query.cursor === "string" ? req.query.cursor : undefined;

  const entries = await prisma.auditLogEntry.findMany({
    where: {
      ...(event ? { event } : {}),
      ...(actorUserId ? { actorUserId } : {}),
      ...(targetType ? { targetType } : {}),
    },
    orderBy: { createdAt: "desc" },
    take: PAGE_SIZE + 1,
    ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
  });

  const hasMore = entries.length > PAGE_SIZE;
  const page = hasMore ? entries.slice(0, PAGE_SIZE) : entries;

  res.json({
    entries: page,
    nextCursor: hasMore ? page[page.length - 1].id : null,
  });
});
