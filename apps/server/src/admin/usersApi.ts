import { Router } from "express";
import { recordAuditEvent } from "../audit/log.js";
import { prisma } from "../db.js";
import { listActiveGrantsForUser, revokeAllOidcStateForUser, revokeGrantForUser } from "../oidc/sessions.js";
import { requirePermission, type RequestWithAdmin } from "../rbac/requirePermission.js";
import { deleteUserAccount } from "../account/deleteAccount.js";

/**
 * Admin read/manage API for end users — view, force-revoke sessions, delete,
 * and see each user's linked connectors and per-client roles (TODO.md
 * Phase 8's "manage users, roles, sessions" item). Role *definitions* live
 * in rolesApi.ts; this file covers viewing a user's assignments and
 * granting/revoking them.
 */
export const usersApiRouter = Router();
usersApiRouter.use(requirePermission("admin:manage_users"));

function serializeUser(user: {
  id: string;
  primaryEmail: string | null;
  emailVerified: boolean;
  displayName: string | null;
  avatarUrl: string | null;
  status: string;
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: user.id,
    primaryEmail: user.primaryEmail,
    emailVerified: user.emailVerified,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    status: user.status,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

usersApiRouter.get("/", async (req, res) => {
  const search = typeof req.query.search === "string" ? req.query.search : undefined;
  const users = await prisma.user.findMany({
    where: search
      ? {
          OR: [
            { primaryEmail: { contains: search, mode: "insensitive" } },
            { displayName: { contains: search, mode: "insensitive" } },
          ],
        }
      : undefined,
    orderBy: { createdAt: "desc" },
    take: 100,
  });
  res.json(users.map(serializeUser));
});

usersApiRouter.get("/:id", async (req, res) => {
  const user = await prisma.user.findUnique({
    where: { id: req.params.id },
    include: {
      linkedIdentities: true,
      userRoles: { include: { role: { include: { client: true } } } },
    },
  });
  if (!user) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  const grants = await listActiveGrantsForUser(user.id);

  res.json({
    ...serializeUser(user),
    linkedIdentities: user.linkedIdentities.map((li) => ({
      id: li.id,
      provider: li.provider,
      providerUserId: li.providerUserId,
      providerUsername: li.providerUsername,
      verifiedVia: li.verifiedVia,
      linkedAt: li.linkedAt,
    })),
    roles: user.userRoles.map((ur) => ({
      roleId: ur.role.id,
      roleName: ur.role.name,
      permissions: ur.role.permissions,
      clientId: ur.role.client.id,
      clientName: ur.role.client.name,
      assignedAt: ur.assignedAt,
    })),
    activeGrants: grants,
  });
});

usersApiRouter.patch("/:id", async (req, res) => {
  const existing = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!existing) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  const body = req.body as { status?: unknown; displayName?: unknown };
  const data: Record<string, unknown> = {};
  if (typeof body.status === "string" && ["ACTIVE", "SUSPENDED", "DELETED"].includes(body.status)) {
    data.status = body.status;
  }
  if (typeof body.displayName === "string") data.displayName = body.displayName;

  const user = await prisma.user.update({ where: { id: req.params.id }, data });

  void recordAuditEvent("admin.user.updated", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "User",
    targetId: user.id,
    metadata: { changedFields: Object.keys(data) },
  });

  res.json(serializeUser(user));
});

usersApiRouter.delete("/:id", async (req, res) => {
  const existing = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!existing) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  const admin = (req as RequestWithAdmin).admin;
  await deleteUserAccount(req.params.id, admin);

  res.status(204).send();
});

usersApiRouter.post("/:id/sessions/revoke-all", async (req, res) => {
  const existing = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!existing) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  await revokeAllOidcStateForUser(req.params.id);

  void recordAuditEvent("session.revoked_all", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "User",
    targetId: req.params.id,
    metadata: { revokedByAdmin: true },
  });

  res.status(204).send();
});

usersApiRouter.post("/:id/sessions/:grantId/revoke", async (req, res) => {
  const revoked = await revokeGrantForUser(req.params.id, req.params.grantId);
  if (!revoked) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  void recordAuditEvent("token.revoked", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "Grant",
    targetId: req.params.grantId,
    metadata: { revokedByAdmin: true, forUserId: req.params.id },
  });

  res.status(204).send();
});

usersApiRouter.post("/:id/roles", async (req, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!user) {
    res.status(404).json({ error: "not_found" });
    return;
  }

  const body = req.body as { roleId?: unknown };
  if (typeof body.roleId !== "string") {
    res.status(400).json({ error: "invalid_body", error_description: "roleId is required" });
    return;
  }
  const role = await prisma.role.findUnique({ where: { id: body.roleId } });
  if (!role) {
    res.status(400).json({ error: "invalid_body", error_description: "unknown roleId" });
    return;
  }

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: user.id, roleId: role.id } },
    update: {},
    create: { userId: user.id, roleId: role.id },
  });

  void recordAuditEvent("admin.role.granted", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "User",
    targetId: user.id,
    metadata: { roleId: role.id, roleName: role.name },
  });

  res.status(204).send();
});

usersApiRouter.delete("/:id/roles/:roleId", async (req, res) => {
  await prisma.userRole.deleteMany({ where: { userId: req.params.id, roleId: req.params.roleId } });

  void recordAuditEvent("admin.role.revoked", {
    actorUserId: (req as RequestWithAdmin).admin?.userId,
    actorClientId: (req as RequestWithAdmin).admin?.clientId,
    targetType: "User",
    targetId: req.params.id,
    metadata: { roleId: req.params.roleId },
  });

  res.status(204).send();
});
