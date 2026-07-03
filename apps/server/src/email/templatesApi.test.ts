import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { prisma } from "../db.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";

const REDIRECT_URI = "http://localhost:3000/callback";
const TEST_EMAIL = "email-templates-api-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

beforeAll(async () => {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "email-templates-api-test-tenant" },
    update: {},
    create: { name: "Email Templates API Test Tenant", slug: "email-templates-api-test-tenant" },
  });

  const clientWithPermission = await prisma.client.upsert({
    where: { clientId: "email-templates-api-with-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Has email:manage_templates",
      clientId: "email-templates-api-with-permission",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid",
      tokenEndpointAuthMethod: "none",
    },
  });

  await prisma.client.upsert({
    where: { clientId: "email-templates-api-without-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Does not have email:manage_templates",
      clientId: "email-templates-api-without-permission",
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
      displayName: "Email Templates API Test User",
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });

  const role = await prisma.role.upsert({
    where: { clientId_name: { clientId: clientWithPermission.id, name: "email-admin" } },
    update: {},
    create: {
      clientId: clientWithPermission.id,
      name: "email-admin",
      permissions: ["email:manage_templates"],
    },
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

describe("Email template admin API: gated by RBAC, not just logged-in-ness", () => {
  it("rejects a request with no bearer token", async () => {
    const res = await request(app).get("/api/admin/email-templates");
    expect(res.status).toBe(401);
  });

  it("rejects a token from a client whose role lacks email:manage_templates", async () => {
    const accessToken = await getAccessTokenFor("email-templates-api-without-permission");
    const res = await request(app)
      .get("/api/admin/email-templates")
      .set("Authorization", `Bearer ${accessToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toBe("insufficient_permission");
  });

  it("rejects an unknown usageType", async () => {
    const accessToken = await getAccessTokenFor("email-templates-api-with-permission");
    const res = await request(app)
      .put("/api/admin/email-templates/NotARealUsageType")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ subject: "x", content: "y" });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_usage_type");
  });

  it("creates/updates a template, then reads it back via GET (single and list)", async () => {
    const accessToken = await getAccessTokenFor("email-templates-api-with-permission");

    const putRes = await request(app)
      .put("/api/admin/email-templates/SignIn")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ subject: "Edited subject {{code}}", content: "<p>Edited {{code}}</p>" });

    expect(putRes.status).toBe(200);
    expect(putRes.body.usageType).toBe("SignIn");
    expect(putRes.body.subject).toBe("Edited subject {{code}}");

    const getRes = await request(app)
      .get("/api/admin/email-templates/SignIn")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.content).toBe("<p>Edited {{code}}</p>");

    const listRes = await request(app)
      .get("/api/admin/email-templates")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(listRes.status).toBe(200);
    expect(listRes.body.some((t: { usageType: string }) => t.usageType === "SignIn")).toBe(true);
  });

  it("previews unsaved edits without persisting them", async () => {
    const accessToken = await getAccessTokenFor("email-templates-api-with-permission");

    const previewRes = await request(app)
      .post("/api/admin/email-templates/SignIn/preview")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ subject: "Draft {{code}}", content: "<p>Draft {{code}}</p>", variables: { code: "999000" } });

    expect(previewRes.status).toBe(200);
    expect(previewRes.body).toEqual({ subject: "Draft 999000", html: "<p>Draft 999000</p>" });

    const stored = await request(app)
      .get("/api/admin/email-templates/SignIn")
      .set("Authorization", `Bearer ${accessToken}`);
    // The draft preview must not have overwritten the persisted template.
    expect(stored.body.subject).not.toBe("Draft {{code}}");
  });

  it("returns 404 previewing a usageType that has no stored template and no draft body", async () => {
    const accessToken = await getAccessTokenFor("email-templates-api-with-permission");
    const res = await request(app)
      .post("/api/admin/email-templates/BindMfa/preview")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({});

    expect(res.status).toBe(404);
  });
});
