import crypto from "node:crypto";
import type { AddressInfo } from "node:net";
import bcrypt from "bcryptjs";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { connectorRegistry } from "../connectors/registry.js";
import { prisma } from "../db.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";

const REDIRECT_URI = "http://localhost:3000/callback";
const TEST_EMAIL = "connectors-api-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

// A real, network-reachable listener (not supertest's in-process fake) is
// needed for the self-referential OIDC connector test below — its real
// discovery fetch needs an actual URL to hit.
let realServer: ReturnType<typeof app.listen>;
let realBaseUrl: string;

beforeAll(async () => {
  realServer = app.listen(0);
  await new Promise<void>((resolve) => realServer.once("listening", resolve));
  const { port } = realServer.address() as AddressInfo;
  realBaseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => realServer.close(() => resolve()));
});

beforeAll(async () => {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "connectors-api-test-tenant" },
    update: {},
    create: { name: "Connectors API Test Tenant", slug: "connectors-api-test-tenant" },
  });

  const clientWithPermission = await prisma.client.upsert({
    where: { clientId: "connectors-api-with-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Has admin:manage_connectors",
      clientId: "connectors-api-with-permission",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid",
      tokenEndpointAuthMethod: "none",
    },
  });

  await prisma.client.upsert({
    where: { clientId: "connectors-api-without-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Does not have admin:manage_connectors",
      clientId: "connectors-api-without-permission",
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
      displayName: "Connectors API Test User",
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });

  const role = await prisma.role.upsert({
    where: { clientId_name: { clientId: clientWithPermission.id, name: "connectors-admin" } },
    update: {},
    create: { clientId: clientWithPermission.id, name: "connectors-admin", permissions: ["admin:manage_connectors"] },
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

describe("Connector management admin API", () => {
  it("rejects a request with no bearer token", async () => {
    const res = await request(app).get("/api/admin/connectors");
    expect(res.status).toBe(401);
  });

  it("rejects a token from a client whose role lacks admin:manage_connectors", async () => {
    const accessToken = await getAccessTokenFor("connectors-api-without-permission");
    const res = await request(app).get("/api/admin/connectors").set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(403);
  });

  it("lists the built-in named presets", async () => {
    const accessToken = await getAccessTokenFor("connectors-api-with-permission");
    const res = await request(app).get("/api/admin/connectors/presets").set("Authorization", `Bearer ${accessToken}`);

    expect(res.status).toBe(200);
    const ids = res.body.map((p: { id: string }) => p.id);
    expect(ids).toEqual(expect.arrayContaining(["discord", "roblox", "twitch", "vpzone"]));
  });

  it("registers a preset-based connector and it appears in the live registry immediately", async () => {
    const accessToken = await getAccessTokenFor("connectors-api-with-permission");
    const res = await request(app)
      .post("/api/admin/connectors")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ presetId: "discord", clientId: "fake-discord-client-id", clientSecret: "fake-discord-secret" });

    expect(res.status).toBe(201);
    expect(res.body.providerId).toBe("discord");
    expect(res.body.displayName).toBe("Discord");
    expect(res.body.clientSecret).toBeUndefined();

    // No restart needed — the mutation reloads the live registry itself.
    expect(connectorRegistry.has("discord")).toBe(true);
  });

  it("rejects registering the same providerId twice", async () => {
    const accessToken = await getAccessTokenFor("connectors-api-with-permission");
    const res = await request(app)
      .post("/api/admin/connectors")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ presetId: "discord", clientId: "another-id", clientSecret: "another-secret" });
    expect(res.status).toBe(409);
  });

  it("rejects a custom OIDC connector whose issuer doesn't actually resolve", async () => {
    const accessToken = await getAccessTokenFor("connectors-api-with-permission");
    const res = await request(app)
      .post("/api/admin/connectors")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({
        providerId: "broken-oidc",
        type: "oidc",
        issuer: "https://this-issuer-should-not-resolve.invalid",
        clientId: "x",
        clientSecret: "y",
        scope: "openid",
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_connector_config");
    expect(connectorRegistry.has("broken-oidc")).toBe(false);
  });

  it("registers a real custom OIDC connector against our own live server (self-referential, proves discovery actually works)", async () => {
    const accessToken = await getAccessTokenFor("connectors-api-with-permission");

    // Register ourselves as our own upstream OIDC connector — a genuine,
    // real discovery fetch against a real spec-compliant server, not a mock.
    const res = await request(app)
      .post("/api/admin/connectors")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({
        providerId: "self-oidc-test",
        type: "oidc",
        issuer: `${realBaseUrl}/oidc`,
        clientId: "test-public-client",
        clientSecret: "unused-for-public-client",
        scope: "openid",
      });

    expect(res.status).toBe(201);
    expect(connectorRegistry.has("self-oidc-test")).toBe(true);
  });

  it("disabling a connector removes it from the live registry without deleting it", async () => {
    const accessToken = await getAccessTokenFor("connectors-api-with-permission");
    const listRes = await request(app).get("/api/admin/connectors").set("Authorization", `Bearer ${accessToken}`);
    const discordRow = listRes.body.find((c: { providerId: string }) => c.providerId === "discord");

    const patchRes = await request(app)
      .patch(`/api/admin/connectors/${discordRow.id}`)
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ enabled: false });

    expect(patchRes.status).toBe(200);
    expect(connectorRegistry.has("discord")).toBe(false);

    const stillExists = await prisma.connector.findUnique({ where: { id: discordRow.id } });
    expect(stillExists).toBeTruthy();
  });

  it("deleting a connector removes it from the database and the live registry", async () => {
    const accessToken = await getAccessTokenFor("connectors-api-with-permission");
    const listRes = await request(app).get("/api/admin/connectors").set("Authorization", `Bearer ${accessToken}`);
    const selfOidcRow = listRes.body.find((c: { providerId: string }) => c.providerId === "self-oidc-test");

    const deleteRes = await request(app)
      .delete(`/api/admin/connectors/${selfOidcRow.id}`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(deleteRes.status).toBe(204);
    expect(connectorRegistry.has("self-oidc-test")).toBe(false);

    const stillExists = await prisma.connector.findUnique({ where: { id: selfOidcRow.id } });
    expect(stillExists).toBeNull();
  });
});
