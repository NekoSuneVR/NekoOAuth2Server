import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { prisma } from "../db.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";

const REDIRECT_URI = "http://localhost:3000/callback";
const TEST_EMAIL = "roles-api-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

let targetClientId: string;

beforeAll(async () => {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "roles-api-test-tenant" },
    update: {},
    create: { name: "Roles API Test Tenant", slug: "roles-api-test-tenant" },
  });

  const clientWithPermission = await prisma.client.upsert({
    where: { clientId: "roles-api-with-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Has admin:manage_users",
      clientId: "roles-api-with-permission",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid",
      tokenEndpointAuthMethod: "none",
    },
  });

  await prisma.client.upsert({
    where: { clientId: "roles-api-without-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Does not have admin:manage_users",
      clientId: "roles-api-without-permission",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid",
      tokenEndpointAuthMethod: "none",
    },
  });

  const targetClient = await prisma.client.upsert({
    where: { clientId: "roles-api-target-project" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Target Project For Roles",
      clientId: "roles-api-target-project",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid",
      tokenEndpointAuthMethod: "none",
    },
  });
  targetClientId = targetClient.id;

  const user = await prisma.user.upsert({
    where: { primaryEmail: TEST_EMAIL },
    update: {},
    create: {
      primaryEmail: TEST_EMAIL,
      emailVerified: true,
      displayName: "Roles API Test User",
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });

  const role = await prisma.role.upsert({
    where: { clientId_name: { clientId: clientWithPermission.id, name: "roles-admin" } },
    update: {},
    create: { clientId: clientWithPermission.id, name: "roles-admin", permissions: ["admin:manage_users"] },
  });

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: user.id, roleId: role.id } },
    update: {},
    create: { userId: user.id, roleId: role.id },
  });
});

async function getAccessTokenFor(clientId: string) {
  const agent = request.agent(app);
  const { verifier, challenge } = pkcePair();
  const { code } = await runAuthorizationRequest(
    agent,
    {
      client_id: clientId,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "openid",
      state: crypto.randomBytes(8).toString("hex"),
      prompt: "consent",
      code_challenge: challenge,
      code_challenge_method: "S256",
    },
    { email: TEST_EMAIL, password: TEST_PASSWORD },
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

describe("Role management admin API", () => {
  it("rejects a request with no bearer token", async () => {
    const res = await request(app).get("/api/admin/roles");
    expect(res.status).toBe(401);
  });

  it("rejects a token from a client whose role lacks admin:manage_users", async () => {
    const accessToken = await getAccessTokenFor("roles-api-without-permission");
    const res = await request(app).get("/api/admin/roles").set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(403);
  });

  it("creates a role scoped to a client", async () => {
    const accessToken = await getAccessTokenFor("roles-api-with-permission");
    const res = await request(app)
      .post("/api/admin/roles")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ clientId: targetClientId, name: "editor", description: "Can edit content", permissions: ["content:edit"] });

    expect(res.status).toBe(201);
    expect(res.body.name).toBe("editor");
    expect(res.body.permissions).toEqual(["content:edit"]);
  });

  it("rejects creating a duplicate role name for the same client", async () => {
    const accessToken = await getAccessTokenFor("roles-api-with-permission");
    const res = await request(app)
      .post("/api/admin/roles")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ clientId: targetClientId, name: "editor", permissions: [] });
    expect(res.status).toBe(409);
  });

  it("lists roles filtered by clientId", async () => {
    const accessToken = await getAccessTokenFor("roles-api-with-permission");
    const res = await request(app)
      .get(`/api/admin/roles?clientId=${targetClientId}`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(200);
    expect(res.body.some((r: { name: string }) => r.name === "editor")).toBe(true);
  });

  it("updates a role's permissions", async () => {
    const accessToken = await getAccessTokenFor("roles-api-with-permission");
    const createRes = await request(app)
      .post("/api/admin/roles")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ clientId: targetClientId, name: "viewer", permissions: ["content:view"] });

    const patchRes = await request(app)
      .patch(`/api/admin/roles/${createRes.body.id}`)
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ permissions: ["content:view", "content:comment"] });

    expect(patchRes.status).toBe(200);
    expect(patchRes.body.permissions).toEqual(["content:view", "content:comment"]);
  });

  it("deletes a role and removes it from the assigned user's role list", async () => {
    const accessToken = await getAccessTokenFor("roles-api-with-permission");
    const createRes = await request(app)
      .post("/api/admin/roles")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ clientId: targetClientId, name: "temp-role", permissions: [] });

    const testUser = await prisma.user.upsert({
      where: { primaryEmail: "roles-api-assignee@example.com" },
      update: {},
      create: { primaryEmail: "roles-api-assignee@example.com", emailVerified: true },
    });
    await prisma.userRole.create({ data: { userId: testUser.id, roleId: createRes.body.id } });

    const deleteRes = await request(app)
      .delete(`/api/admin/roles/${createRes.body.id}`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(deleteRes.status).toBe(204);

    const remaining = await prisma.userRole.findMany({ where: { userId: testUser.id } });
    expect(remaining).toHaveLength(0);
  });

  it("returns 404 for an unknown role id", async () => {
    const accessToken = await getAccessTokenFor("roles-api-with-permission");
    const res = await request(app).get("/api/admin/roles/does-not-exist").set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(404);
  });
});
