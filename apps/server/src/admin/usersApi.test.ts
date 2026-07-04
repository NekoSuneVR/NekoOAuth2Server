import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { prisma } from "../db.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";

const REDIRECT_URI = "http://localhost:3000/callback";
const ADMIN_EMAIL = "users-api-admin@example.com";
const ADMIN_PASSWORD = "correct-horse-battery-staple";
const TARGET_EMAIL = "users-api-target@example.com";
const TARGET_PASSWORD = "another-correct-horse";

let adminClientId: string;
let targetUserId: string;
let targetClientDbId: string;

beforeAll(async () => {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "users-api-test-tenant" },
    update: {},
    create: { name: "Users API Test Tenant", slug: "users-api-test-tenant" },
  });

  const clientWithPermission = await prisma.client.upsert({
    where: { clientId: "users-api-with-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Has admin:manage_users",
      clientId: "users-api-with-permission",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid",
      tokenEndpointAuthMethod: "none",
    },
  });
  adminClientId = clientWithPermission.clientId;

  await prisma.client.upsert({
    where: { clientId: "users-api-without-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Does not have admin:manage_users",
      clientId: "users-api-without-permission",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid",
      tokenEndpointAuthMethod: "none",
    },
  });

  const targetClient = await prisma.client.upsert({
    where: { clientId: "users-api-target-project" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Target Project",
      clientId: "users-api-target-project",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid profile email",
      tokenEndpointAuthMethod: "none",
    },
  });
  targetClientDbId = targetClient.id;

  const adminUser = await prisma.user.upsert({
    where: { primaryEmail: ADMIN_EMAIL },
    update: {},
    create: {
      primaryEmail: ADMIN_EMAIL,
      emailVerified: true,
      displayName: "Users API Admin",
      passwordHash: await bcrypt.hash(ADMIN_PASSWORD, 10),
    },
  });

  const role = await prisma.role.upsert({
    where: { clientId_name: { clientId: clientWithPermission.id, name: "users-admin" } },
    update: {},
    create: { clientId: clientWithPermission.id, name: "users-admin", permissions: ["admin:manage_users"] },
  });

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: adminUser.id, roleId: role.id } },
    update: {},
    create: { userId: adminUser.id, roleId: role.id },
  });

  const targetUser = await prisma.user.upsert({
    where: { primaryEmail: TARGET_EMAIL },
    update: {},
    create: {
      primaryEmail: TARGET_EMAIL,
      emailVerified: true,
      displayName: "Target User",
      passwordHash: await bcrypt.hash(TARGET_PASSWORD, 10),
    },
  });
  targetUserId = targetUser.id;
});

async function getAccessTokenFor(clientId: string, email: string, password: string, scope = "openid") {
  const agent = request.agent(app);
  const { verifier, challenge } = pkcePair();
  const { code } = await runAuthorizationRequest(
    agent,
    {
      client_id: clientId,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope,
      state: crypto.randomBytes(8).toString("hex"),
      prompt: "consent",
      code_challenge: challenge,
      code_challenge_method: "S256",
    },
    { email, password },
    REDIRECT_URI,
  );

  const tokenRes = await agent
    .post("/oidc/token")
    .type("form")
    .send({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      client_id: clientId,
      code_verifier: verifier,
    });

  return tokenRes.body.access_token as string;
}

async function adminToken() {
  return getAccessTokenFor(adminClientId, ADMIN_EMAIL, ADMIN_PASSWORD);
}

describe("User management admin API", () => {
  it("rejects a request with no bearer token", async () => {
    const res = await request(app).get("/api/admin/users");
    expect(res.status).toBe(401);
  });

  it("rejects a token from a client whose role lacks admin:manage_users", async () => {
    const accessToken = await getAccessTokenFor("users-api-without-permission", TARGET_EMAIL, TARGET_PASSWORD);
    const res = await request(app).get("/api/admin/users").set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(403);
  });

  it("lists users, including the target user", async () => {
    const accessToken = await adminToken();
    const res = await request(app).get("/api/admin/users").set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(res.body.some((u: { id: string }) => u.id === targetUserId)).toBe(true);
  });

  it("searches users by email", async () => {
    const accessToken = await adminToken();
    const res = await request(app)
      .get("/api/admin/users?search=users-api-target")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].id).toBe(targetUserId);
  });

  it("returns a user's detail including linked identities, roles, and active grants", async () => {
    await getAccessTokenFor("users-api-target-project", TARGET_EMAIL, TARGET_PASSWORD, "openid profile email");

    const accessToken = await adminToken();
    const res = await request(app).get(`/api/admin/users/${targetUserId}`).set("Authorization", `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body.primaryEmail).toBe(TARGET_EMAIL);
    expect(Array.isArray(res.body.linkedIdentities)).toBe(true);
    expect(Array.isArray(res.body.roles)).toBe(true);
    expect(res.body.activeGrants.some((g: { clientId: string }) => g.clientId === "users-api-target-project")).toBe(true);
  });

  it("returns 404 for an unknown user id", async () => {
    const accessToken = await adminToken();
    const res = await request(app).get("/api/admin/users/does-not-exist").set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(404);
  });

  it("suspends a user via PATCH and records an audit event", async () => {
    const accessToken = await adminToken();
    const res = await request(app)
      .patch(`/api/admin/users/${targetUserId}`)
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ status: "SUSPENDED" });

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("SUSPENDED");

    const entries = await prisma.auditLogEntry.findMany({
      where: { event: "admin.user.updated", targetId: targetUserId },
    });
    expect(entries.length).toBeGreaterThan(0);

    // Reset back to ACTIVE for the rest of this suite's tests.
    await prisma.user.update({ where: { id: targetUserId }, data: { status: "ACTIVE" } });
  });

  it("grants and revokes a role for a user", async () => {
    const accessToken = await adminToken();
    const role = await prisma.role.upsert({
      where: { clientId_name: { clientId: targetClientDbId, name: "member" } },
      update: {},
      create: { clientId: targetClientDbId, name: "member", permissions: ["self:read"] },
    });

    const grantRes = await request(app)
      .post(`/api/admin/users/${targetUserId}/roles`)
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ roleId: role.id });
    expect(grantRes.status).toBe(204);

    const afterGrant = await request(app).get(`/api/admin/users/${targetUserId}`).set("Authorization", `Bearer ${accessToken}`);
    expect(afterGrant.body.roles.some((r: { roleId: string }) => r.roleId === role.id)).toBe(true);

    const revokeRes = await request(app)
      .delete(`/api/admin/users/${targetUserId}/roles/${role.id}`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(revokeRes.status).toBe(204);

    const afterRevoke = await request(app).get(`/api/admin/users/${targetUserId}`).set("Authorization", `Bearer ${accessToken}`);
    expect(afterRevoke.body.roles.some((r: { roleId: string }) => r.roleId === role.id)).toBe(false);
  });

  it("force-revokes a single session (grant) for a user", async () => {
    const targetToken = await getAccessTokenFor("users-api-target-project", TARGET_EMAIL, TARGET_PASSWORD, "openid profile email");
    expect((await request(app).get("/oidc/me").set("Authorization", `Bearer ${targetToken}`)).status).toBe(200);

    const accessToken = await adminToken();
    const detailRes = await request(app).get(`/api/admin/users/${targetUserId}`).set("Authorization", `Bearer ${accessToken}`);
    const grant = detailRes.body.activeGrants.find((g: { clientId: string }) => g.clientId === "users-api-target-project");
    expect(grant).toBeTruthy();

    const revokeRes = await request(app)
      .post(`/api/admin/users/${targetUserId}/sessions/${grant.grantId}/revoke`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(revokeRes.status).toBe(204);

    expect((await request(app).get("/oidc/me").set("Authorization", `Bearer ${targetToken}`)).status).toBe(401);
  });

  it("force-revokes every session for a user (log out everywhere)", async () => {
    const targetToken = await getAccessTokenFor("users-api-target-project", TARGET_EMAIL, TARGET_PASSWORD, "openid profile email");
    expect((await request(app).get("/oidc/me").set("Authorization", `Bearer ${targetToken}`)).status).toBe(200);

    const accessToken = await adminToken();
    const res = await request(app)
      .post(`/api/admin/users/${targetUserId}/sessions/revoke-all`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(204);

    expect((await request(app).get("/oidc/me").set("Authorization", `Bearer ${targetToken}`)).status).toBe(401);
  });

  it("admin-deletes a user, recording the admin as the actor", async () => {
    const doomedUser = await prisma.user.create({
      data: { primaryEmail: "users-api-doomed@example.com", emailVerified: true },
    });

    const accessToken = await adminToken();
    const res = await request(app).delete(`/api/admin/users/${doomedUser.id}`).set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(204);

    const stillExists = await prisma.user.findUnique({ where: { id: doomedUser.id } });
    expect(stillExists).toBeNull();

    const entries = await prisma.auditLogEntry.findMany({
      where: { event: "account.deleted", targetId: doomedUser.id },
    });
    expect(entries.length).toBeGreaterThan(0);
    expect(entries[0].actorClientId).not.toBeNull();
  });
});
