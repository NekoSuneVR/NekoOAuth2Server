import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { prisma } from "../db.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";

const REDIRECT_URI = "http://localhost:3000/callback";
const TEST_EMAIL = "rbac-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

beforeAll(async () => {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "rbac-tenant" },
    update: {},
    create: { name: "RBAC Tenant", slug: "rbac-tenant" },
  });

  const projectA = await prisma.client.upsert({
    where: { clientId: "rbac-project-a" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "RBAC Project A",
      clientId: "rbac-project-a",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid profile email roles",
      tokenEndpointAuthMethod: "none",
    },
  });

  await prisma.client.upsert({
    where: { clientId: "rbac-project-b" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "RBAC Project B",
      clientId: "rbac-project-b",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid profile email roles",
      tokenEndpointAuthMethod: "none",
    },
  });

  const user = await prisma.user.upsert({
    where: { primaryEmail: TEST_EMAIL },
    update: {},
    create: {
      primaryEmail: TEST_EMAIL,
      emailVerified: true,
      displayName: "RBAC Test User",
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });

  // The "admin" role — and its admin:access permission — is scoped to
  // Project A ONLY. Never assigned anywhere for Project B.
  const adminRole = await prisma.role.upsert({
    where: { clientId_name: { clientId: projectA.id, name: "admin" } },
    update: {},
    create: {
      clientId: projectA.id,
      name: "admin",
      permissions: ["admin:access"],
    },
  });

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: user.id, roleId: adminRole.id } },
    update: {},
    create: { userId: user.id, roleId: adminRole.id },
  });
});

async function getAccessTokenFor(clientId: string) {
  const agent = request.agent(app);
  const { verifier, challenge } = pkcePair();
  const state = crypto.randomBytes(8).toString("hex");

  const { code } = await runAuthorizationRequest(
    agent,
    {
      client_id: clientId,
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "openid profile email roles",
      state,
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

  return { agent, accessToken: tokenRes.body.access_token as string };
}

describe("RBAC: a role granted in one project has no effect when authenticating to another", () => {
  it("shows the admin role in userinfo when authenticating to Project A (where it was granted)", async () => {
    const { agent, accessToken } = await getAccessTokenFor("rbac-project-a");
    const userinfo = await agent.get("/oidc/me").set("Authorization", `Bearer ${accessToken}`);

    expect(userinfo.status).toBe(200);
    expect(userinfo.body.roles).toEqual(["admin"]);
    expect(userinfo.body.permissions).toEqual(["admin:access"]);
  });

  it("shows NO roles in userinfo for the same user authenticating to Project B", async () => {
    const { agent, accessToken } = await getAccessTokenFor("rbac-project-b");
    const userinfo = await agent.get("/oidc/me").set("Authorization", `Bearer ${accessToken}`);

    expect(userinfo.status).toBe(200);
    expect(userinfo.body.roles).toEqual([]);
    expect(userinfo.body.permissions).toEqual([]);
  });

  it("allows the Project A access token through a permission-protected endpoint", async () => {
    const { accessToken } = await getAccessTokenFor("rbac-project-a");
    const res = await request(app).get("/api/internal/admin-ping").set("Authorization", `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it("rejects the SAME user's Project B access token from the same protected endpoint", async () => {
    const { accessToken } = await getAccessTokenFor("rbac-project-b");
    const res = await request(app).get("/api/internal/admin-ping").set("Authorization", `Bearer ${accessToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toBe("insufficient_permission");
  });
});
