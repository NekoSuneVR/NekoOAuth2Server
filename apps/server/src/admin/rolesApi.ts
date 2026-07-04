import { Router } from "express";
import { recordAuditEvent } from "../audit/log.js";
import { prisma } from "../db.js";
import { requirePermission, type RequestWithAdmin } from "../rbac/requirePermission.js";

/**
 * Admin CRUD for role *definitions* (permission sets scoped to one Client —
 * see the Role model comment in schema.prisma). Assigning/revoking a role
 * to/from a specific user lives in usersApi.ts, since that mutation is keyed
 * off the user, not the role. Gated by the same `admin:manage_users`
 * permission as usersApi.ts — this project doesn't split "manage users" from
 * "manage the roles users get assigned" into separate permissions.
 */
export const rolesApiRouter = Router();
rolesApiRouter.use(requirePermission("admin:manage_users"));

function serializeRole(role: {
  id: string;
  clientId: string;
  name: string;
  description: string | null;
  permissions: string[];
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: role.id,
    clientId: role.clientId,
    name: role.name,
    description: role.description,
    permissions: role.permissions,
    createdAt: role.createdAt,
    updatedAt: role.updatedAt,
  };
}

rolesApiRouter.get("/", async (req, res) => {
  const clientId = typeof req.query.clientId === "string" ? req.query.clientId : undefined;
  const roles = await prisma.role.findMany({
    where: clientId ? { clientId } : undefined,
    orderBy: { createdAt: "desc" },
  });
  res.json(roles.map(serializeRole));
});

rolesApiRouter.get("/:id", async (req, res) => {
  const role = await prisma.role.findUnique({
    where: { id: req.params.id },
    include: { userRoles: { include: { user: true } } },
  });
  if (!role) {
    res.status(404).json({ error: "not_found" });
    return;
  }
  res.json({
    ...serializeRole(role),
    assignedUsers: role.userRoles.map((ur) => ({
      userId: ur.user.id,
      primaryEmail: ur.user.primaryEmail,
      displayName: ur.user.displayName,
      assignedAt: ur.assignedAt,
    })),
  });
});

rolesApiRouter.post("/", async (req, res) => {
  const body = req.body as {
    clientId?: unknown;
    name?: unknown;
    description?: unknown;
    permissions?: unknown;
  };

  if (typeof body.clientId !== "string" || !body.clientId) {
    res.status(400).json({ error: "invalid_body", error_description: "clientId is required" });
    return;
  }
  if (typeof body.name !== "string" || !body.name.trim()) {
    res.status(400).json({ error: "invalid_body", error_description: "name is required" });
    return;
  }
  const client = await prisma.client.findUnique({ where: { id: body.clientId } });
  if (!client) {
    res.status(400).json({ error: "invalid_body", error_description: "unknown clientId" });
    return;
  }

  const permissions = Array.isArray(body.permissions) ? body.permissions.filter((p) => typeof p === "string") : [];

  const existing = await prisma.role.findUnique({ where: { clientId_name: { clientId: client.id, name: body.name } } });
  if (existing) {
    res.status(409).json({ error: "already_exists", error_description: `a role named "${body.name}" already exists for this client` });
    return;
  }

  const role = await prisma.role.create({
    data: {
      clientId: client.id,
      name: body.name,
      description: typeof body.description === "string" ? body.description : null,
      permissions,
    },
  });

  void recordAuditEvent("admin.role.granted", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "Role",
    targetId: role.id,
    metadata: { created: true, clientId: role.clientId, name: role.name, permissions: role.permissions },
  });

  res.status(201).json(serializeRole(role));
});

rolesApiRouter.patch("/:id", async (req, res) => {
  const existing = await prisma.role.findUnique({ where: { id: req.params.id } });
  if (!existing) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  const body = req.body as { name?: unknown; description?: unknown; permissions?: unknown };
  const data: Record<string, unknown> = {};
  if (typeof body.name === "string" && body.name.trim()) data.name = body.name;
  if (typeof body.description === "string") data.description = body.description;
  if (Array.isArray(body.permissions)) data.permissions = body.permissions.filter((p) => typeof p === "string");

  const role = await prisma.role.update({ where: { id: req.params.id }, data });

  void recordAuditEvent("admin.role.granted", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "Role",
    targetId: role.id,
    metadata: { updated: true, changedFields: Object.keys(data) },
  });

  res.json(serializeRole(role));
});

rolesApiRouter.delete("/:id", async (req, res) => {
  const existing = await prisma.role.findUnique({ where: { id: req.params.id } });
  if (!existing) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  await prisma.$transaction([
    prisma.userRole.deleteMany({ where: { roleId: req.params.id } }),
    prisma.role.delete({ where: { id: req.params.id } }),
  ]);

  void recordAuditEvent("admin.role.revoked", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "Role",
    targetId: req.params.id,
    metadata: { deleted: true, clientId: existing.clientId, name: existing.name },
  });

  res.status(204).send();
});
