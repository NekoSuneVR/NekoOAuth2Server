import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { recordAuditEvent } from "../audit/log.js";
import { prisma } from "../db.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";

const REDIRECT_URI = "http://localhost:3000/callback";
const TEST_EMAIL = "audit-log-api-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

beforeAll(async () => {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "audit-log-api-test-tenant" },
    update: {},
    create: { name: "Audit Log API Test Tenant", slug: "audit-log-api-test-tenant" },
  });

  const clientWithPermission = await prisma.client.upsert({
    where: { clientId: "audit-log-api-with-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Has admin:view_audit_log",
      clientId: "audit-log-api-with-permission",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid",
      tokenEndpointAuthMethod: "none",
    },
  });

  await prisma.client.upsert({
    where: { clientId: "audit-log-api-without-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Does not have admin:view_audit_log",
      clientId: "audit-log-api-without-permission",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid",
      tokenEndpointAuthMethod: "none",
    },
  });

  const user = await prisma.user.upsert({
    where: { primaryEmail: TEST_EMAIL },
    update: {},
    create: {
      primaryEmail: TEST_EMAIL,
      emailVerified: true,
      displayName: "Audit Log API Test User",
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });

  const role = await prisma.role.upsert({
    where: { clientId_name: { clientId: clientWithPermission.id, name: "audit-viewer" } },
    update: {},
    create: { clientId: clientWithPermission.id, name: "audit-viewer", permissions: ["admin:view_audit_log"] },
  });

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: user.id, roleId: role.id } },
    update: {},
    create: { userId: user.id, roleId: role.id },
  });

  // Seed a batch of real, distinguishable audit rows to filter/paginate over.
  for (let i = 0; i < 5; i++) {
    await recordAuditEvent("admin.client.created", {
      actorUserId: user.id,
      targetType: "Client",
      targetId: `seeded-client-${i}`,
      metadata: { seedIndex: i },
    });
  }
  await recordAuditEvent("login.failure", { metadata: { email: "someone@example.com" } });
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

describe("Audit log admin API", () => {
  it("rejects a request with no bearer token", async () => {
    const res = await request(app).get("/api/admin/audit-log");
    expect(res.status).toBe(401);
  });

  it("rejects a token from a client whose role lacks admin:view_audit_log", async () => {
    const accessToken = await getAccessTokenFor("audit-log-api-without-permission");
    const res = await request(app).get("/api/admin/audit-log").set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(403);
  });

  it("lists recent entries, most recent first", async () => {
    const accessToken = await getAccessTokenFor("audit-log-api-with-permission");
    const res = await request(app).get("/api/admin/audit-log").set("Authorization", `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body.entries.length).toBeGreaterThanOrEqual(6);
    const timestamps = res.body.entries.map((e: { createdAt: string }) => new Date(e.createdAt).getTime());
    expect([...timestamps]).toEqual([...timestamps].sort((a, b) => b - a));
  });

  it("filters by event type", async () => {
    const accessToken = await getAccessTokenFor("audit-log-api-with-permission");
    const res = await request(app)
      .get("/api/admin/audit-log")
      .query({ event: "login.failure" })
      .set("Authorization", `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    expect(res.body.entries.length).toBeGreaterThanOrEqual(1);
    for (const entry of res.body.entries) {
      expect(entry.event).toBe("login.failure");
    }
  });

  it("filters by actorUserId and paginates with a cursor", async () => {
    const accessToken = await getAccessTokenFor("audit-log-api-with-permission");
    const user = await prisma.user.findUniqueOrThrow({ where: { primaryEmail: TEST_EMAIL } });

    const firstPage = await request(app)
      .get("/api/admin/audit-log")
      .query({ actorUserId: user.id, event: "admin.client.created" })
      .set("Authorization", `Bearer ${accessToken}`);

    expect(firstPage.status).toBe(200);
    expect(firstPage.body.entries.length).toBe(5);
    expect(firstPage.body.nextCursor).toBeNull();

    for (const entry of firstPage.body.entries) {
      expect(entry.actorUserId).toBe(user.id);
    }
  });
});
