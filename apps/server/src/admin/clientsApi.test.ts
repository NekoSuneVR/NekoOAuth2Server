import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { prisma } from "../db.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";

const REDIRECT_URI = "http://localhost:3000/callback";
const TEST_EMAIL = "clients-api-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

beforeAll(async () => {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "clients-api-test-tenant" },
    update: {},
    create: { name: "Clients API Test Tenant", slug: "clients-api-test-tenant" },
  });

  const clientWithPermission = await prisma.client.upsert({
    where: { clientId: "clients-api-with-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Has admin:manage_clients",
      clientId: "clients-api-with-permission",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid",
      tokenEndpointAuthMethod: "none",
    },
  });

  await prisma.client.upsert({
    where: { clientId: "clients-api-without-permission" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Does not have admin:manage_clients",
      clientId: "clients-api-without-permission",
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
      displayName: "Clients API Test User",
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });

  const role = await prisma.role.upsert({
    where: { clientId_name: { clientId: clientWithPermission.id, name: "clients-admin" } },
    update: {},
    create: { clientId: clientWithPermission.id, name: "clients-admin", permissions: ["admin:manage_clients"] },
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

describe("Client management admin API", () => {
  it("rejects a request with no bearer token", async () => {
    const res = await request(app).get("/api/admin/clients");
    expect(res.status).toBe(401);
  });

  it("rejects a token from a client whose role lacks admin:manage_clients", async () => {
    const accessToken = await getAccessTokenFor("clients-api-without-permission");
    const res = await request(app).get("/api/admin/clients").set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(403);
    expect(res.body.error).toBe("insufficient_permission");
  });

  it("creates a client, returning the plaintext secret exactly once", async () => {
    const accessToken = await getAccessTokenFor("clients-api-with-permission");

    const createRes = await request(app)
      .post("/api/admin/clients")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ name: "Newly Registered Project", redirectUris: ["https://example.com/callback"] });

    expect(createRes.status).toBe(201);
    expect(createRes.body.name).toBe("Newly Registered Project");
    expect(createRes.body.hasSecret).toBe(true);
    expect(typeof createRes.body.clientSecret).toBe("string");
    expect(createRes.body.clientId).toMatch(/^newly-registered-project-[0-9a-f]{8}$/);

    const listRes = await request(app).get("/api/admin/clients").set("Authorization", `Bearer ${accessToken}`);
    expect(listRes.status).toBe(200);
    const created = listRes.body.find((c: { id: string }) => c.id === createRes.body.id);
    expect(created).toBeTruthy();
    // The list/get views never include the raw secret, only whether one is set.
    expect(created.clientSecret).toBeUndefined();
    expect(created.hasSecret).toBe(true);
  });

  it("creates a public client (no secret) when isConfidential is false", async () => {
    const accessToken = await getAccessTokenFor("clients-api-with-permission");

    const res = await request(app)
      .post("/api/admin/clients")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({
        name: "Public SPA Project",
        redirectUris: ["https://spa.example.com/callback"],
        isConfidential: false,
        tokenEndpointAuthMethod: "none",
      });

    expect(res.status).toBe(201);
    expect(res.body.hasSecret).toBe(false);
    expect(res.body.clientSecret).toBeNull();
  });

  it("rejects creating a client with no redirect URIs", async () => {
    const accessToken = await getAccessTokenFor("clients-api-with-permission");
    const res = await request(app)
      .post("/api/admin/clients")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ name: "No Redirects" });
    expect(res.status).toBe(400);
  });

  it("updates a client's name and redirect URIs", async () => {
    const accessToken = await getAccessTokenFor("clients-api-with-permission");
    const createRes = await request(app)
      .post("/api/admin/clients")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ name: "Original Name", redirectUris: ["https://example.com/callback"] });

    const patchRes = await request(app)
      .patch(`/api/admin/clients/${createRes.body.id}`)
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ name: "Updated Name", redirectUris: ["https://example.com/new-callback"] });

    expect(patchRes.status).toBe(200);
    expect(patchRes.body.name).toBe("Updated Name");
    expect(patchRes.body.redirectUris).toEqual(["https://example.com/new-callback"]);
  });

  it("rotates a confidential client's secret, invalidating the old one", async () => {
    const accessToken = await getAccessTokenFor("clients-api-with-permission");
    const createRes = await request(app)
      .post("/api/admin/clients")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({ name: "Rotate Me", redirectUris: ["https://example.com/callback"] });
    const originalSecret = createRes.body.clientSecret as string;

    const rotateRes = await request(app)
      .post(`/api/admin/clients/${createRes.body.id}/rotate-secret`)
      .set("Authorization", `Bearer ${accessToken}`);

    expect(rotateRes.status).toBe(200);
    expect(rotateRes.body.clientSecret).not.toBe(originalSecret);

    const stored = await prisma.client.findUnique({ where: { id: createRes.body.id } });
    expect(stored?.clientSecret).toBe(rotateRes.body.clientSecret);
  });

  it("refuses to rotate a secret for a public (no-secret) client", async () => {
    const accessToken = await getAccessTokenFor("clients-api-with-permission");
    const createRes = await request(app)
      .post("/api/admin/clients")
      .set("Authorization", `Bearer ${accessToken}`)
      .send({
        name: "Public No Secret",
        redirectUris: ["https://example.com/callback"],
        isConfidential: false,
        tokenEndpointAuthMethod: "none",
      });

    const rotateRes = await request(app)
      .post(`/api/admin/clients/${createRes.body.id}/rotate-secret`)
      .set("Authorization", `Bearer ${accessToken}`);
    expect(rotateRes.status).toBe(400);
  });

  it("returns 404 for an unknown client id", async () => {
    const accessToken = await getAccessTokenFor("clients-api-with-permission");
    const res = await request(app)
      .get("/api/admin/clients/does-not-exist")
      .set("Authorization", `Bearer ${accessToken}`);
    expect(res.status).toBe(404);
  });
});
