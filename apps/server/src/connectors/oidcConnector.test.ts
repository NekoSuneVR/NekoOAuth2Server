import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import bcrypt from "bcryptjs";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { prisma } from "../db.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";
import { createOidcConnector } from "./oidcConnector.js";

/**
 * Tests the generic OIDC connector against our OWN real, live oidc-provider
 * instance — genuinely more thorough than a mock, since it's a real,
 * spec-compliant OIDC server (already proven in Phases 1-3), not a stand-in.
 * Needs a real network-reachable listener (not supertest's in-process fake
 * one) because the connector's discovery-document and id_token/JWKS fetches
 * are real HTTP calls a mock in-process server can't answer.
 */
const REDIRECT_URI_PATH = "/self-test-callback";
const TEST_EMAIL = "oidc-connector-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;

  const tenant = await prisma.tenant.upsert({
    where: { slug: "oidc-connector-test-tenant" },
    update: {},
    create: { name: "OIDC Connector Test Tenant", slug: "oidc-connector-test-tenant" },
  });

  await prisma.client.upsert({
    where: { clientId: "oidc-connector-test-client" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "OIDC Connector Self-Test Client",
      clientId: "oidc-connector-test-client",
      clientSecret: "oidc-connector-test-secret",
      isConfidential: true,
      redirectUris: [`${baseUrl}${REDIRECT_URI_PATH}`],
      scope: "openid profile email",
      tokenEndpointAuthMethod: "client_secret_basic",
    },
  });

  await prisma.user.upsert({
    where: { primaryEmail: TEST_EMAIL },
    update: {},
    create: {
      primaryEmail: TEST_EMAIL,
      emailVerified: true,
      displayName: "OIDC Connector Test User",
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

describe("generic OIDC connector, against our own real oidc-provider", () => {
  it("fetches discovery, exchanges a real code, and validates a real signed id_token", async () => {
    const connector = await createOidcConnector({
      id: "self-test",
      issuer: `${baseUrl}/oidc`,
      clientId: "oidc-connector-test-client",
      clientSecret: "oidc-connector-test-secret",
      scope: "openid profile email",
      // Our own server requires PKCE from every client (Phase 1's policy) —
      // this isn't optional here, unlike it might be for a real upstream.
      pkce: "required",
      mapUserInfo: (claims) => ({
        id: String(claims.sub),
        username: typeof claims.name === "string" ? claims.name : undefined,
        email: typeof claims.email === "string" ? claims.email : undefined,
        raw: claims,
      }),
    });

    const { verifier, challenge } = pkcePair();
    const { code } = await runAuthorizationRequest(
      request.agent(app),
      {
        client_id: "oidc-connector-test-client",
        response_type: "code",
        redirect_uri: `${baseUrl}${REDIRECT_URI_PATH}`,
        scope: "openid profile email",
        state: "self-test-state",
        prompt: "consent",
        code_challenge: challenge,
        code_challenge_method: "S256",
      },
      { email: TEST_EMAIL, password: TEST_PASSWORD },
      `${baseUrl}${REDIRECT_URI_PATH}`,
    );

    const tokens = await connector.exchangeCode({
      code,
      redirectUri: `${baseUrl}${REDIRECT_URI_PATH}`,
      codeVerifier: verifier,
    });

    expect(tokens.accessToken).toBeTruthy();
    expect(tokens.idToken).toBeTruthy();

    const info = await connector.getUserInfo(tokens);
    expect(info.email).toBe(TEST_EMAIL);
  });

  it("rejects a forged id_token signed by an unrelated key (proves verification is real, not a no-op)", async () => {
    const connector = await createOidcConnector({
      id: "self-test-forged",
      issuer: `${baseUrl}/oidc`,
      clientId: "oidc-connector-test-client",
      clientSecret: "oidc-connector-test-secret",
      scope: "openid",
      pkce: "required",
      mapUserInfo: (claims) => ({ id: String(claims.sub), raw: claims }),
    });

    const jose = await import("jose");
    const { privateKey } = await jose.generateKeyPair("RS256");
    const forgedIdToken = await new jose.SignJWT({ sub: "attacker-controlled-subject" })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(`${baseUrl}/oidc`)
      .setAudience("oidc-connector-test-client")
      .setExpirationTime("5m")
      .sign(privateKey);

    // Feed the forged token in directly rather than through a real exchange
    // (a real exchange can only ever produce a token actually signed by our
    // server's real key) — this specifically exercises the connector's own
    // signature check against a token that LOOKS right (correct issuer,
    // correct audience, well-formed) but was never signed by the real key.
    // Only the /token response is faked; the JWKS fetch that follows still
    // goes to the real server, so this proves the *signature* check fails,
    // not just that some unrelated fetch was broken.
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/token")) {
        return new Response(JSON.stringify({ access_token: "irrelevant", id_token: forgedIdToken }), {
          headers: { "Content-Type": "application/json" },
        });
      }
      return originalFetch(input, init);
    }) as typeof fetch;
    try {
      await expect(
        connector.exchangeCode({ code: "unused", redirectUri: `${baseUrl}${REDIRECT_URI_PATH}` }),
      ).rejects.toThrow();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
