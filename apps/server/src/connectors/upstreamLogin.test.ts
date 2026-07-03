import http from "node:http";
import type { AddressInfo } from "node:net";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { prisma } from "../db.js";
import { pkcePair } from "../testSupport/httpAuthFlow.js";
import { createOAuth2Connector } from "./oauth2Connector.js";
import { registerConnector } from "./registry.js";

/**
 * Proves the actual wiring (login page -> start -> callback -> User/
 * LinkedIdentity creation -> interaction resumes) works end to end, using a
 * real local mock provider standing in for Discord/Roblox/etc. — there are
 * no real upstream credentials in this sandbox, but this exercises the exact
 * same code path a real provider would go through.
 */
const REDIRECT_URI = "http://localhost:3000/callback";
const MOCK_PROVIDER_ID = "mock-upstream";
const MOCK_UPSTREAM_USER = { id: "mock-upstream-user-1", username: "mockupstream", email: "mockupstream@example.com" };

let mockProviderServer: http.Server;
let mockProviderBaseUrl: string;

function toPath(location: string) {
  if (location.startsWith("http://") || location.startsWith("https://")) {
    const url = new URL(location);
    return `${url.pathname}${url.search}`;
  }
  return location;
}

beforeAll(async () => {
  mockProviderServer = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");

    if (url.pathname === "/authorize") {
      const redirectUri = url.searchParams.get("redirect_uri")!;
      const state = url.searchParams.get("state")!;
      const dest = new URL(redirectUri);
      dest.searchParams.set("code", "mock-upstream-code");
      dest.searchParams.set("state", state);
      res.writeHead(302, { Location: dest.toString() });
      res.end();
      return;
    }

    if (url.pathname === "/token" && req.method === "POST") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ access_token: "mock-upstream-access-token", expires_in: 3600 }));
      return;
    }

    if (url.pathname === "/userinfo") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(MOCK_UPSTREAM_USER));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => mockProviderServer.listen(0, resolve));
  const { port } = mockProviderServer.address() as AddressInfo;
  mockProviderBaseUrl = `http://127.0.0.1:${port}`;

  registerConnector(
    MOCK_PROVIDER_ID,
    createOAuth2Connector({
      id: MOCK_PROVIDER_ID,
      clientId: "mock-client-id",
      clientSecret: "mock-client-secret",
      authorizationEndpoint: `${mockProviderBaseUrl}/authorize`,
      tokenEndpoint: `${mockProviderBaseUrl}/token`,
      userInfoEndpoint: `${mockProviderBaseUrl}/userinfo`,
      scope: "identify",
      pkce: "unsupported",
      mapUserInfo: (raw) => {
        const user = raw as typeof MOCK_UPSTREAM_USER;
        return { id: user.id, username: user.username, email: user.email, raw };
      },
    }),
  );

  const tenant = await prisma.tenant.upsert({
    where: { slug: "upstream-login-test-tenant" },
    update: {},
    create: { name: "Upstream Login Test Tenant", slug: "upstream-login-test-tenant" },
  });

  await prisma.client.upsert({
    where: { clientId: "upstream-login-test-client" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "Upstream Login Test Client",
      clientId: "upstream-login-test-client",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      tokenEndpointAuthMethod: "none",
    },
  });
});

afterAll(() => new Promise<void>((resolve) => mockProviderServer.close(() => resolve())));

/** Drives an already-started authorization flow to completion via upstream login. */
async function completeViaUpstreamLogin(agent: ReturnType<typeof request.agent>) {
  const { challenge } = pkcePair();
  const authRes = await agent.get("/oidc/auth").query({
    client_id: "upstream-login-test-client",
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    scope: "openid",
    state: "upstream-test-state",
    prompt: "consent",
    code_challenge: challenge,
    code_challenge_method: "S256",
  });

  const interactionLocation = authRes.headers.location as string;
  const uid = interactionLocation.split("/interaction/")[1]!.split("/")[0];

  const loginPage = await agent.get(toPath(interactionLocation));
  expect(loginPage.text).toContain(`/oidc/interaction/${uid}/upstream/${MOCK_PROVIDER_ID}`);

  const startRes = await agent.get(`/oidc/interaction/${uid}/upstream/${MOCK_PROVIDER_ID}`);
  expect(startRes.status).toBe(302);
  expect(startRes.headers.location).toContain(mockProviderBaseUrl);

  // The mock provider is a REAL separate server — fetch its redirect for
  // real, but don't follow it (nothing is listening on our own app's
  // configured issuer host during this test); replay just the path+query
  // against our own app instead, exactly like a browser would deliver it.
  const mockRes = await fetch(startRes.headers.location as string, { redirect: "manual" });
  const callbackLocation = mockRes.headers.get("location")!;

  let location: string | undefined = toPath(callbackLocation);
  let res = await agent.get(location);
  location = res.headers.location as string | undefined;

  for (let hops = 0; hops < 10 && location && !location.startsWith(REDIRECT_URI); hops += 1) {
    const path = toPath(location);
    if (path.includes("/interaction/")) {
      const interactionUid = path.split("/interaction/")[1]!.split("/")[0];
      res = await agent.post(`/oidc/interaction/${interactionUid}/confirm`).type("form").send({});
    } else {
      res = await agent.get(path);
    }
    location = res.headers.location as string | undefined;
  }

  if (!location || !location.startsWith(REDIRECT_URI)) {
    throw new Error(`upstream login flow did not reach ${REDIRECT_URI}, stuck at ${location}`);
  }
  return new URL(location).searchParams.get("code")!;
}

describe("Upstream connector wired into login: Sign in with <provider>", () => {
  it("creates a new User + LinkedIdentity on first login via the mock upstream provider", async () => {
    const agent = request.agent(app);
    const code = await completeViaUpstreamLogin(agent);
    expect(code).toBeTruthy();

    const linked = await prisma.linkedIdentity.findUnique({
      where: { provider_providerUserId: { provider: MOCK_PROVIDER_ID, providerUserId: MOCK_UPSTREAM_USER.id } },
    });
    expect(linked).toBeTruthy();

    const user = await prisma.user.findUnique({ where: { id: linked!.userId } });
    expect(user?.primaryEmail).toBe(MOCK_UPSTREAM_USER.email);
  });

  it("reuses the SAME User on a second login via the same upstream identity (no duplicate account)", async () => {
    const firstLinked = await prisma.linkedIdentity.findUnique({
      where: { provider_providerUserId: { provider: MOCK_PROVIDER_ID, providerUserId: MOCK_UPSTREAM_USER.id } },
    });

    const agent = request.agent(app);
    await completeViaUpstreamLogin(agent);

    const secondLinked = await prisma.linkedIdentity.findUnique({
      where: { provider_providerUserId: { provider: MOCK_PROVIDER_ID, providerUserId: MOCK_UPSTREAM_USER.id } },
    });

    expect(secondLinked!.userId).toBe(firstLinked!.userId);
    const userCount = await prisma.user.count({ where: { primaryEmail: MOCK_UPSTREAM_USER.email } });
    expect(userCount).toBe(1);
  });
});
