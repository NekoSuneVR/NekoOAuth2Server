import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { prisma } from "../db.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";

const REDIRECT_URI = "http://localhost:3000/callback";
const TEST_EMAIL = "smtp-config-api-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

beforeAll(async () => {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "smtp-config-api-test-tenant" },
    update: {},
    create: { name: "SMTP Config API Test Tenant", slug: "smtp-config-api-test-tenant" },
  });

  const client = await prisma.client.upsert({
    where: { clientId: "smtp-config-api-with-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Has email:manage_smtp",
      clientId: "smtp-config-api-with-permission",
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
      displayName: "SMTP Config API Test User",
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });

  const role = await prisma.role.upsert({
    where: { clientId_name: { clientId: client.id, name: "smtp-admin" } },
    update: {},
    create: { clientId: client.id, name: "smtp-admin", permissions: ["email:manage_smtp"] },
  });

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: user.id, roleId: role.id } },
    update: {},
    create: { userId: user.id, roleId: role.id },
  });
});

async function getAccessToken() {
  const agent = request.agent(app);
  const { verifier, challenge } = pkcePair();
  const { code } = await runAuthorizationRequest(
    agent,
    {
      client_id: "smtp-config-api-with-permission",
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
      client_id: "smtp-config-api-with-permission",
      code_verifier: verifier,
    });

  return tokenRes.body.access_token as string;
}

describe("SMTP config admin API", () => {
  it("returns 404 before any config has been saved", async () => {
    const accessToken = await getAccessToken();
    const res = await request(app).get("/api/admin/smtp-config").set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(404);
  });

  it("saves a config via PUT and never echoes the password back", async () => {
    const accessToken = await getAccessToken();

    const putRes = await request(app)
      .put("/api/admin/smtp-config")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({
        host: "smtp.example.com",
        port: 587,
        secure: false,
        username: "apikey",
        password: "super-secret-password",
        fromAddress: "noreply@nekosunevr.co.uk",
        fromName: "NekoSuneVR",
      });

    expect(putRes.status).toBe(200);
    expect(putRes.body.host).toBe("smtp.example.com");
    expect(putRes.body.hasPassword).toBe(true);
    expect(putRes.body.password).toBeUndefined();

    const getRes = await request(app).get("/api/admin/smtp-config").set("Authorization", `Bearer ${accessToken}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.hasPassword).toBe(true);
    expect(getRes.body.password).toBeUndefined();

    const raw = await prisma.smtpConfig.findUnique({ where: { id: "default" } });
    expect(raw?.password).toBe("super-secret-password");
  });

  it("a follow-up PUT without a password keeps the previously saved one", async () => {
    const accessToken = await getAccessToken();

    const putRes = await request(app)
      .put("/api/admin/smtp-config")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ host: "smtp2.example.com", port: 2525, fromAddress: "noreply@nekosunevr.co.uk" });

    expect(putRes.status).toBe(200);
    expect(putRes.body.host).toBe("smtp2.example.com");
    expect(putRes.body.hasPassword).toBe(true);

    const raw = await prisma.smtpConfig.findUnique({ where: { id: "default" } });
    expect(raw?.password).toBe("super-secret-password");
  });

  it("rejects a body missing required fields", async () => {
    const accessToken = await getAccessToken();
    const res = await request(app)
      .put("/api/admin/smtp-config")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ host: "smtp.example.com" });

    expect(res.status).toBe(400);
  });
});
