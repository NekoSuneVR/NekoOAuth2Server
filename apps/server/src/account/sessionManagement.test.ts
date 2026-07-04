import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { prisma } from "../db.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";

const REDIRECT_URI = "http://localhost:3000/callback";
const TEST_EMAIL = "session-mgmt-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

beforeAll(async () => {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "session-mgmt-test-tenant" },
    update: {},
    create: { name: "Session Mgmt Test Tenant", slug: "session-mgmt-test-tenant" },
  });

  for (const clientId of ["session-mgmt-client-a", "session-mgmt-client-b"]) {
    await prisma.client.upsert({
      where: { clientId },
      update: {},
      create: {
        tenantId: tenant.id,
        name: clientId,
        clientId,
        clientSecret: null,
        isConfidential: false,
        redirectUris: [REDIRECT_URI],
        scope: "openid profile email",
        tokenEndpointAuthMethod: "none",
      },
    });
  }

  await prisma.user.upsert({
    where: { primaryEmail: TEST_EMAIL },
    update: {},
    create: {
      primaryEmail: TEST_EMAIL,
      emailVerified: true,
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
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
      scope: "openid profile email",
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

async function loginPortalAgent() {
  const agent = request.agent(app);
  await agent.post("/account/login").type("form").send({ email: TEST_EMAIL, password: TEST_PASSWORD });
  return agent;
}

describe("Account portal: session management", () => {
  it("lists an active grant and revoking it kills the access token issued under it", async () => {
    const accessToken = await getAccessTokenFor("session-mgmt-client-a");

    const meBefore = await request(app).get("/oidc/me").set("Authorization", `Bearer ${accessToken}`);
    expect(meBefore.status).toBe(200);

    const portalAgent = await loginPortalAgent();
    const accountPage = await portalAgent.get("/account");
    expect(accountPage.text).toContain("session-mgmt-client-a");

    const grantIdMatch = accountPage.text.match(/\/account\/sessions\/([^/]+)\/revoke/);
    expect(grantIdMatch).toBeTruthy();

    const revokeRes = await portalAgent.post(`/account/sessions/${grantIdMatch![1]}/revoke`);
    expect(revokeRes.status).toBe(302);

    const meAfter = await request(app).get("/oidc/me").set("Authorization", `Bearer ${accessToken}`);
    expect(meAfter.status).toBe(401);

    const accountPageAfter = await portalAgent.get("/account");
    expect(accountPageAfter.text).not.toContain("session-mgmt-client-a");
  });

  it("cannot revoke another user's grant", async () => {
    const otherUserEmail = "session-mgmt-other-user@example.com";
    await prisma.user.upsert({
      where: { primaryEmail: otherUserEmail },
      update: {},
      create: { primaryEmail: otherUserEmail, emailVerified: true, passwordHash: await bcrypt.hash(TEST_PASSWORD, 10) },
    });

    const accessToken = await getAccessTokenFor("session-mgmt-client-b");
    const meBefore = await request(app).get("/oidc/me").set("Authorization", `Bearer ${accessToken}`);
    expect(meBefore.status).toBe(200);

    // A DIFFERENT logged-in user tries to guess/revoke the grant above.
    const otherAgent = request.agent(app);
    await otherAgent.post("/account/login").type("form").send({ email: otherUserEmail, password: TEST_PASSWORD });

    const portalAgent = await loginPortalAgent();
    const accountPage = await portalAgent.get("/account");
    const grantIdMatch = accountPage.text.match(/\/account\/sessions\/([^/]+)\/revoke/);
    expect(grantIdMatch).toBeTruthy();

    await otherAgent.post(`/account/sessions/${grantIdMatch![1]}/revoke`);

    // Still alive — the grant belongs to the first user, not otherAgent's.
    const meAfter = await request(app).get("/oidc/me").set("Authorization", `Bearer ${accessToken}`);
    expect(meAfter.status).toBe(200);
  });

  it("log out everywhere revokes every grant and clears the portal session", async () => {
    const tokenA = await getAccessTokenFor("session-mgmt-client-a");
    const tokenB = await getAccessTokenFor("session-mgmt-client-b");

    expect((await request(app).get("/oidc/me").set("Authorization", `Bearer ${tokenA}`)).status).toBe(200);
    expect((await request(app).get("/oidc/me").set("Authorization", `Bearer ${tokenB}`)).status).toBe(200);

    const portalAgent = await loginPortalAgent();
    const revokeAllRes = await portalAgent.post("/account/sessions/revoke-all");
    expect(revokeAllRes.status).toBe(302);
    expect(revokeAllRes.headers.location).toBe("/account/login");

    expect((await request(app).get("/oidc/me").set("Authorization", `Bearer ${tokenA}`)).status).toBe(401);
    expect((await request(app).get("/oidc/me").set("Authorization", `Bearer ${tokenB}`)).status).toBe(401);

    // The portal's own session cookie was cleared too.
    const accountPageAfter = await portalAgent.get("/account");
    expect(accountPageAfter.status).toBe(302);
    expect(accountPageAfter.headers.location).toBe("/account/login");
  });
});
