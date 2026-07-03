import http from "node:http";
import type { AddressInfo } from "node:net";
import bcrypt from "bcryptjs";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { createOAuth2Connector } from "../connectors/oauth2Connector.js";
import { registerConnector } from "../connectors/registry.js";
import { prisma } from "../db.js";

const TEST_PASSWORD = "correct-horse-battery-staple";
const MOCK_PROVIDER_ID = "mock-linking-provider";
const MOCK_UPSTREAM_ID = "mock-linking-upstream-user-1";

let mockServer: http.Server;
let mockBaseUrl: string;

function toPath(location: string) {
  if (location.startsWith("http://") || location.startsWith("https://")) {
    const url = new URL(location);
    return `${url.pathname}${url.search}`;
  }
  return location;
}

beforeAll(async () => {
  mockServer = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname === "/authorize") {
      const redirectUri = url.searchParams.get("redirect_uri")!;
      const state = url.searchParams.get("state")!;
      const dest = new URL(redirectUri);
      dest.searchParams.set("code", "mock-code");
      dest.searchParams.set("state", state);
      res.writeHead(302, { Location: dest.toString() });
      res.end();
      return;
    }
    if (url.pathname === "/token" && req.method === "POST") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: "mock-access-token" }));
      return;
    }
    if (url.pathname === "/userinfo") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: MOCK_UPSTREAM_ID, username: "linkeduser" }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => mockServer.listen(0, resolve));
  const { port } = mockServer.address() as AddressInfo;
  mockBaseUrl = `http://127.0.0.1:${port}`;

  registerConnector(
    MOCK_PROVIDER_ID,
    createOAuth2Connector({
      id: MOCK_PROVIDER_ID,
      clientId: "mock-client-id",
      clientSecret: "mock-client-secret",
      authorizationEndpoint: `${mockBaseUrl}/authorize`,
      tokenEndpoint: `${mockBaseUrl}/token`,
      userInfoEndpoint: `${mockBaseUrl}/userinfo`,
      scope: "identify",
      pkce: "unsupported",
      mapUserInfo: (raw) => {
        const user = raw as { id: string; username: string };
        return { id: user.id, username: user.username, raw };
      },
    }),
  );
});

afterAll(() => new Promise<void>((resolve) => mockServer.close(() => resolve())));

async function loginAgent(email: string) {
  const agent = request.agent(app);
  await agent.post("/account/login").type("form").send({ email, password: TEST_PASSWORD });
  return agent;
}

async function linkViaMockProvider(agent: ReturnType<typeof request.agent>) {
  const startRes = await agent.get(`/account/link/${MOCK_PROVIDER_ID}`);
  expect(startRes.status).toBe(302);
  expect(startRes.headers.location).toContain(mockBaseUrl);

  const mockRes = await fetch(startRes.headers.location as string, { redirect: "manual" });
  const callbackLocation = mockRes.headers.get("location")!;
  return agent.get(toPath(callbackLocation));
}

describe("Account linking: attaching an upstream identity to an already-signed-in account", () => {
  it("links a new upstream identity to the logged-in account", async () => {
    const email = "linking-test-user@example.com";
    await prisma.user.upsert({
      where: { primaryEmail: email },
      update: {},
      create: { primaryEmail: email, emailVerified: true, passwordHash: await bcrypt.hash(TEST_PASSWORD, 10) },
    });

    const agent = await loginAgent(email);
    const callbackRes = await linkViaMockProvider(agent);
    expect(callbackRes.status).toBe(302);
    expect(callbackRes.headers.location).toBe("/account");

    const accountPage = await agent.get("/account");
    expect(accountPage.text).toContain(MOCK_PROVIDER_ID);
    expect(accountPage.text).toContain("linkeduser");

    const user = await prisma.user.findUnique({ where: { primaryEmail: email } });
    const linked = await prisma.linkedIdentity.findUnique({
      where: { provider_providerUserId: { provider: MOCK_PROVIDER_ID, providerUserId: MOCK_UPSTREAM_ID } },
    });
    expect(linked?.userId).toBe(user!.id);
  });

  it("refuses to link an upstream identity that's already linked to a DIFFERENT account", async () => {
    const secondEmail = "linking-test-user-2@example.com";
    await prisma.user.upsert({
      where: { primaryEmail: secondEmail },
      update: {},
      create: { primaryEmail: secondEmail, emailVerified: true, passwordHash: await bcrypt.hash(TEST_PASSWORD, 10) },
    });

    // The mock upstream identity (MOCK_UPSTREAM_ID) is already linked to the
    // first test's user from the previous test — attempting to link the SAME
    // upstream identity to this different account must be rejected.
    const agent = await loginAgent(secondEmail);
    const callbackRes = await linkViaMockProvider(agent);

    expect(callbackRes.status).toBe(409);

    const linked = await prisma.linkedIdentity.findUnique({
      where: { provider_providerUserId: { provider: MOCK_PROVIDER_ID, providerUserId: MOCK_UPSTREAM_ID } },
    });
    const secondUser = await prisma.user.findUnique({ where: { primaryEmail: secondEmail } });
    expect(linked?.userId).not.toBe(secondUser!.id);
  });

  it("unlinks an identity, and it's gone from the account page", async () => {
    const email = "linking-test-user@example.com";
    const agent = await loginAgent(email);
    const user = await prisma.user.findUnique({ where: { primaryEmail: email } });
    const linked = await prisma.linkedIdentity.findUnique({
      where: { provider_providerUserId: { provider: MOCK_PROVIDER_ID, providerUserId: MOCK_UPSTREAM_ID } },
    });
    expect(linked?.userId).toBe(user!.id);

    const unlinkRes = await agent.post(`/account/linked-identities/${linked!.id}/unlink`);
    expect(unlinkRes.status).toBe(302);

    const accountPage = await agent.get("/account");
    // Not in the *linked* list — it correctly reappears as linkABLE again,
    // so a blanket "page doesn't mention this provider at all" check is wrong.
    expect(accountPage.text).not.toContain(`${MOCK_PROVIDER_ID}: linkeduser`);
    expect(accountPage.text).toContain(`Link ${MOCK_PROVIDER_ID}`);

    expect(
      await prisma.linkedIdentity.findUnique({
        where: { provider_providerUserId: { provider: MOCK_PROVIDER_ID, providerUserId: MOCK_UPSTREAM_ID } },
      }),
    ).toBeNull();
  });
});
