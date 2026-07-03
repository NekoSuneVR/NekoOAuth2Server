import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";
import { prisma } from "../db.js";

const REDIRECT_URI = "http://localhost:3000/callback";
const TEST_EMAIL = "profile-api-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

beforeAll(async () => {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "profile-api-test-tenant" },
    update: {},
    create: { name: "Profile API Test Tenant", slug: "profile-api-test-tenant" },
  });

  await prisma.client.upsert({
    where: { clientId: "profile-api-test-client" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Profile API Test Client",
      clientId: "profile-api-test-client",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid profile email",
      tokenEndpointAuthMethod: "none",
    },
  });

  await prisma.user.upsert({
    where: { primaryEmail: TEST_EMAIL },
    update: {},
    create: {
      primaryEmail: TEST_EMAIL,
      emailVerified: true,
      displayName: "Original Name",
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });
});

async function getAccessToken(scope: string) {
  const agent = request.agent(app);
  const { verifier, challenge } = pkcePair();
  const { code } = await runAuthorizationRequest(
    agent,
    {
      client_id: "profile-api-test-client",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope,
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
      client_id: "profile-api-test-client",
      code_verifier: verifier,
    });

  return tokenRes.body.access_token as string;
}

describe("Profile API: downstream apps can update fields they're granted scope for", () => {
  it("updates name/picture with a token that has the profile scope", async () => {
    const accessToken = await getAccessToken("openid profile");

    const res = await request(app)
      .patch("/api/profile")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ name: "Updated Name", picture: "https://example.com/new-avatar.png" });

    expect(res.status).toBe(200);
    expect(res.body.name).toBe("Updated Name");

    const user = await prisma.user.findUnique({ where: { primaryEmail: TEST_EMAIL } });
    expect(user?.displayName).toBe("Updated Name");
    expect(user?.avatarUrl).toBe("https://example.com/new-avatar.png");
  });

  it("refuses to update email with a token that only has the profile scope", async () => {
    const accessToken = await getAccessToken("openid profile");

    const res = await request(app)
      .patch("/api/profile")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ email: "hijacked@example.com" });

    expect(res.status).toBe(403);
    expect(res.body.error).toBe("insufficient_scope");

    const user = await prisma.user.findUnique({ where: { primaryEmail: TEST_EMAIL } });
    expect(user?.primaryEmail).toBe(TEST_EMAIL);
  });

  it("rejects requests with no access token", async () => {
    const res = await request(app).patch("/api/profile").send({ name: "Nope" });
    expect(res.status).toBe(401);
  });
});
