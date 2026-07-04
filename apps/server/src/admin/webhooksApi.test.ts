import crypto from "node:crypto";
import http, { type Server } from "node:http";
import type { AddressInfo } from "node:net";
import bcrypt from "bcryptjs";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { prisma } from "../db.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";

const REDIRECT_URI = "http://localhost:3000/callback";
const TEST_EMAIL = "webhooks-api-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

let mockReceiver: Server;
let mockReceiverUrl: string;
let receivedCount = 0;
let targetClientId: string;

beforeAll(async () => {
  mockReceiver = http.createServer((req, res) => {
    receivedCount += 1;
    req.on("data", () => {});
    req.on("end", () => res.writeHead(200).end("ok"));
  });
  await new Promise<void>((resolve) => mockReceiver.listen(0, "127.0.0.1", resolve));
  const { port } = mockReceiver.address() as AddressInfo;
  mockReceiverUrl = `http://127.0.0.1:${port}/webhook`;

  const tenant = await prisma.tenant.upsert({
    where: { slug: "webhooks-api-test-tenant" },
    update: {},
    create: { name: "Webhooks API Test Tenant", slug: "webhooks-api-test-tenant" },
  });

  const clientWithPermission = await prisma.client.upsert({
    where: { clientId: "webhooks-api-with-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Has admin:manage_webhooks",
      clientId: "webhooks-api-with-permission",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid",
      tokenEndpointAuthMethod: "none",
    },
  });

  await prisma.client.upsert({
    where: { clientId: "webhooks-api-without-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Does not have admin:manage_webhooks",
      clientId: "webhooks-api-without-permission",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid",
      tokenEndpointAuthMethod: "none",
    },
  });

  const targetClient = await prisma.client.upsert({
    where: { clientId: "webhooks-api-target-client" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Target Project For A Webhook",
      clientId: "webhooks-api-target-client",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
    },
  });
  targetClientId = targetClient.id;

  const user = await prisma.user.upsert({
    where: { primaryEmail: TEST_EMAIL },
    update: {},
    create: {
      primaryEmail: TEST_EMAIL,
      emailVerified: true,
      displayName: "Webhooks API Test User",
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });

  const role = await prisma.role.upsert({
    where: { clientId_name: { clientId: clientWithPermission.id, name: "webhooks-admin" } },
    update: {},
    create: { clientId: clientWithPermission.id, name: "webhooks-admin", permissions: ["admin:manage_webhooks"] },
  });

  await prisma.userRole.upsert({
    where: { userId_roleId: { userId: user.id, roleId: role.id } },
    update: {},
    create: { userId: user.id, roleId: role.id },
  });
});

afterAll(async () => {
  await new Promise<void>((resolve) => mockReceiver.close(() => resolve()));
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

describe("Webhook management admin API", () => {
  it("rejects a request with no bearer token", async () => {
    const res = await request(app).get("/api/admin/webhooks");
    expect(res.status).toBe(401);
  });

  it("rejects a token from a client whose role lacks admin:manage_webhooks", async () => {
    const accessToken = await getAccessTokenFor("webhooks-api-without-permission");
    const res = await request(app).get("/api/admin/webhooks").set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(403);
  });

  it("rejects registering a webhook pointed at a private/internal URL", async () => {
    const accessToken = await getAccessTokenFor("webhooks-api-with-permission");
    const res = await request(app)
      .post("/api/admin/webhooks")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ clientId: targetClientId, url: "https://169.254.169.254/latest/meta-data" });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("unsafe_url");
  });

  it("registers a webhook, returning the secret exactly once", async () => {
    const accessToken = await getAccessTokenFor("webhooks-api-with-permission");
    const createRes = await request(app)
      .post("/api/admin/webhooks")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ clientId: targetClientId, url: mockReceiverUrl });

    expect(createRes.status).toBe(201);
    expect(typeof createRes.body.secret).toBe("string");
    expect(createRes.body.url).toBe(mockReceiverUrl);
    expect(createRes.body.enabled).toBe(true);

    const getRes = await request(app)
      .get(`/api/admin/webhooks/${createRes.body.id}`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.secret).toBeUndefined();
  });

  it("updates a webhook's URL and enabled state", async () => {
    const accessToken = await getAccessTokenFor("webhooks-api-with-permission");
    const createRes = await request(app)
      .post("/api/admin/webhooks")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ clientId: targetClientId, url: mockReceiverUrl });

    const patchRes = await request(app)
      .patch(`/api/admin/webhooks/${createRes.body.id}`)
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ enabled: false });

    expect(patchRes.status).toBe(200);
    expect(patchRes.body.enabled).toBe(false);
  });

  it("rotates a webhook's secret", async () => {
    const accessToken = await getAccessTokenFor("webhooks-api-with-permission");
    const createRes = await request(app)
      .post("/api/admin/webhooks")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ clientId: targetClientId, url: mockReceiverUrl });
    const originalSecret = createRes.body.secret as string;

    const rotateRes = await request(app)
      .post(`/api/admin/webhooks/${createRes.body.id}/rotate-secret`)
      .set("Authorization", `Bearer ${accessToken}`);

    expect(rotateRes.status).toBe(200);
    expect(rotateRes.body.secret).not.toBe(originalSecret);
  });

  it("lists delivery history and can resend a past delivery", async () => {
    const accessToken = await getAccessTokenFor("webhooks-api-with-permission");

    // A dedicated client+user for this test only — deliverUserDeletedWebhook
    // fans out to every *enabled* endpoint registered for a client, and
    // earlier tests in this file leave their own endpoints registered
    // against targetClientId, which would otherwise also receive this
    // delivery and make receivedCount unpredictable.
    const tenant = await prisma.tenant.findUniqueOrThrow({ where: { slug: "webhooks-api-test-tenant" } });
    const isolatedClient = await prisma.client.create({
      data: {
        tenantId: tenant.id,
        name: "Isolated Delivery Test Client",
        clientId: `webhooks-api-isolated-${crypto.randomBytes(4).toString("hex")}`,
        clientSecret: null,
        isConfidential: false,
        redirectUris: [REDIRECT_URI],
      },
    });
    const isolatedUser = await prisma.user.create({
      data: { primaryEmail: `webhooks-isolated-${crypto.randomBytes(4).toString("hex")}@example.com`, emailVerified: true },
    });

    const createRes = await request(app)
      .post("/api/admin/webhooks")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ clientId: isolatedClient.id, url: mockReceiverUrl });

    await prisma.clientConsent.create({
      data: { userId: isolatedUser.id, clientId: isolatedClient.id, grantedScopes: ["openid"] },
    });

    const { deliverUserDeletedWebhook } = await import("../webhooks/deliver.js");
    receivedCount = 0;
    await deliverUserDeletedWebhook(isolatedUser.id);
    expect(receivedCount).toBe(1);

    const deliveriesRes = await request(app)
      .get(`/api/admin/webhooks/${createRes.body.id}/deliveries`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(deliveriesRes.status).toBe(200);
    expect(deliveriesRes.body.length).toBeGreaterThanOrEqual(1);
    const deliveryId = deliveriesRes.body[0].id;

    const resendRes = await request(app)
      .post(`/api/admin/webhooks/${createRes.body.id}/deliveries/${deliveryId}/resend`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(resendRes.status).toBe(202);
    expect(receivedCount).toBe(2);
  });

  it("deletes a webhook endpoint", async () => {
    const accessToken = await getAccessTokenFor("webhooks-api-with-permission");
    const createRes = await request(app)
      .post("/api/admin/webhooks")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ clientId: targetClientId, url: mockReceiverUrl });

    const deleteRes = await request(app)
      .delete(`/api/admin/webhooks/${createRes.body.id}`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(deleteRes.status).toBe(204);

    const getRes = await request(app)
      .get(`/api/admin/webhooks/${createRes.body.id}`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(getRes.status).toBe(404);
  });
});
