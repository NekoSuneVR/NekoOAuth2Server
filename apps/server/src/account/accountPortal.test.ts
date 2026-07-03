import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import bcrypt from "bcryptjs";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { prisma } from "../db.js";

const TEST_EMAIL = "account-portal-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

let webhookServer: http.Server;
let webhookBaseUrl: string;
let receivedWebhookRequests: Array<{ body: string; signature: string | undefined }> = [];

beforeAll(async () => {
  webhookServer = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => { raw += chunk; });
    req.on("end", () => {
      receivedWebhookRequests.push({ body: raw, signature: req.headers["x-neko-signature"] as string | undefined });
      res.writeHead(200);
      res.end();
    });
  });
  await new Promise<void>((resolve) => webhookServer.listen(0, resolve));
  const { port } = webhookServer.address() as AddressInfo;
  webhookBaseUrl = `http://127.0.0.1:${port}/webhook`;
});

afterAll(() => new Promise<void>((resolve) => webhookServer.close(() => resolve())));

describe("Account portal: login, view, unauthenticated access", () => {
  it("redirects unauthenticated visitors to /account/login", async () => {
    const res = await request(app).get("/account");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/account/login");
  });

  it("logs in and shows the account page", async () => {
    await prisma.user.upsert({
      where: { primaryEmail: TEST_EMAIL },
      update: {},
      create: {
        primaryEmail: TEST_EMAIL,
        emailVerified: true,
        displayName: "Account Portal Test User",
        passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
      },
    });

    const agent = request.agent(app);
    const loginRes = await agent.post("/account/login").type("form").send({ email: TEST_EMAIL, password: TEST_PASSWORD });
    expect(loginRes.status).toBe(302);
    expect(loginRes.headers.location).toBe("/account");

    const accountRes = await agent.get("/account");
    expect(accountRes.status).toBe(200);
    expect(accountRes.text).toContain(TEST_EMAIL);
    expect(accountRes.text).toContain("Account Portal Test User");
  });

  it("rejects the wrong password", async () => {
    const res = await request(app).post("/account/login").type("form").send({ email: TEST_EMAIL, password: "wrong" });
    expect(res.status).toBe(401);
  });
});

describe("Self-service account deletion with webhook cascade", () => {
  it("deletes the account, revokes active grants/sessions, and notifies subscribed webhooks", async () => {
    receivedWebhookRequests = [];

    const tenant = await prisma.tenant.upsert({
      where: { slug: "account-deletion-test-tenant" },
      update: {},
      create: { name: "Account Deletion Test Tenant", slug: "account-deletion-test-tenant" },
    });

    const client = await prisma.client.upsert({
      where: { clientId: "account-deletion-test-client" },
      update: {},
      create: {
        tenantId: tenant.id,
        name: "Account Deletion Test Client",
        clientId: "account-deletion-test-client",
        clientSecret: null,
        isConfidential: false,
        redirectUris: ["http://localhost:3000/callback"],
      },
    });

    const webhookSecret = "test-webhook-secret";
    await prisma.webhookEndpoint.create({
      data: { clientId: client.id, url: webhookBaseUrl, secret: webhookSecret },
    });

    const email = "delete-me-test@example.com";
    const user = await prisma.user.create({
      data: { primaryEmail: email, emailVerified: true, passwordHash: await bcrypt.hash(TEST_PASSWORD, 10) },
    });

    // This is the structured signal the deletion cascade actually reads —
    // "this client has a real relationship with this user" (see webhooks/deliver.ts).
    await prisma.clientConsent.create({
      data: { userId: user.id, clientId: client.id, grantedScopes: ["openid"] },
    });

    // A live grant + session, to prove deletion actually revokes them rather
    // than just deleting the User row and leaving tokens/cookies valid.
    await prisma.oidcModel.create({
      data: { type: "Grant", id: "test-grant-1", payload: { accountId: user.id, clientId: client.clientId } },
    });
    await prisma.oidcModel.create({
      data: {
        type: "AccessToken",
        id: "test-token-1",
        payload: { accountId: user.id, grantId: "test-grant-1" },
        grantId: "test-grant-1",
      },
    });
    await prisma.oidcModel.create({
      data: { type: "Session", id: "test-session-1", payload: { accountId: user.id }, uid: "test-session-uid-1" },
    });

    const agent = request.agent(app);
    await agent.post("/account/login").type("form").send({ email, password: TEST_PASSWORD });

    const deleteRes = await agent.post("/account/delete");
    expect(deleteRes.status).toBe(200);

    // User + owned rows actually gone.
    expect(await prisma.user.findUnique({ where: { id: user.id } })).toBeNull();
    expect(await prisma.clientConsent.findMany({ where: { userId: user.id } })).toHaveLength(0);

    // Active grant/token/session revoked, not just left to expire naturally.
    expect(await prisma.oidcModel.findUnique({ where: { type_id: { type: "Grant", id: "test-grant-1" } } })).toBeNull();
    expect(
      await prisma.oidcModel.findUnique({ where: { type_id: { type: "AccessToken", id: "test-token-1" } } }),
    ).toBeNull();
    expect(
      await prisma.oidcModel.findUnique({ where: { type_id: { type: "Session", id: "test-session-1" } } }),
    ).toBeNull();

    // The webhook actually fired, with a valid signature over the exact body.
    expect(receivedWebhookRequests).toHaveLength(1);
    const [delivery] = receivedWebhookRequests;
    const expectedSignature = crypto.createHmac("sha256", webhookSecret).update(delivery.body).digest("hex");
    expect(delivery.signature).toBe(`sha256=${expectedSignature}`);
    const payload = JSON.parse(delivery.body);
    expect(payload.event).toBe("user.deleted");
    expect(payload.data.sub).toBe(user.id);

    // And it's logged.
    const deliveryLog = await prisma.webhookDelivery.findMany({ where: { event: "user.deleted" } });
    expect(deliveryLog.some((d) => d.statusCode === 200)).toBe(true);

    // Session cookie no longer works.
    const afterDeleteRes = await agent.get("/account");
    expect(afterDeleteRes.status).toBe(302);
    expect(afterDeleteRes.headers.location).toBe("/account/login");
  });
});
