import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import * as jose from "jose";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { config } from "../config.js";
import { prisma } from "../db.js";
import { pkcePair, runAuthorizationRequest } from "../testSupport/httpAuthFlow.js";
import { INTERNAL_API_RESOURCE } from "./provider.js";

const REDIRECT_URI = "http://localhost:3000/callback";
const TEST_EMAIL = "e2e-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

beforeAll(async () => {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "e2e-tenant" },
    update: {},
    create: { name: "E2E Tenant", slug: "e2e-tenant" },
  });

  await prisma.client.upsert({
    where: { clientId: "e2e-public-client" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "E2E Public Client",
      clientId: "e2e-public-client",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      scope: "openid profile email offline_access",
      tokenEndpointAuthMethod: "none",
    },
  });

  await prisma.client.upsert({
    where: { clientId: "e2e-service-client" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "E2E Service Client",
      clientId: "e2e-service-client",
      clientSecret: "e2e-service-secret",
      isConfidential: true,
      redirectUris: [],
      grantTypes: ["client_credentials"],
      responseTypes: [],
      scope: "internal:read internal:write",
      tokenEndpointAuthMethod: "client_secret_basic",
    },
  });

  await prisma.user.upsert({
    where: { primaryEmail: TEST_EMAIL },
    update: {},
    create: {
      primaryEmail: TEST_EMAIL,
      emailVerified: true,
      displayName: "E2E Test User",
      avatarUrl: "https://example.com/avatar.png",
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });
});

async function authorizeAndExchange(scope: string) {
  const agent = request.agent(app);
  const { verifier, challenge } = pkcePair();
  const state = crypto.randomBytes(8).toString("hex");

  const { code } = await runAuthorizationRequest(
    agent,
    {
      client_id: "e2e-public-client",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope,
      state,
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
      client_id: "e2e-public-client",
      code_verifier: verifier,
    });

  return { agent, tokenRes };
}

describe("Authorization code flow, end to end, against a real test client", () => {
  it("completes login + consent over real HTTP and exchanges the code for tokens", async () => {
    const { tokenRes } = await authorizeAndExchange("openid profile email");

    expect(tokenRes.status).toBe(200);
    expect(tokenRes.body.access_token).toBeTruthy();
    expect(tokenRes.body.id_token).toBeTruthy();
    expect(tokenRes.body.token_type).toBe("Bearer");
  });

  it("issues an id_token that verifies against our own JWKS endpoint (proves the keys are real, not just present)", async () => {
    const { agent, tokenRes } = await authorizeAndExchange("openid profile email");

    const jwksRes = await agent.get("/oidc/jwks");
    const jwk = jwksRes.body.keys[0];
    const publicKey = await jose.importJWK({ ...jwk, d: undefined }, "RS256");

    // By design, the code-flow id_token only carries `sub` + auth claims —
    // profile/email claims are delivered via userinfo (see the scope/claims
    // describe block below), not embedded here. This test is specifically
    // about the JWKS/signature being real and verifiable, not about claims.
    const { payload } = await jose.jwtVerify(tokenRes.body.id_token, publicKey, {
      issuer: config.issuer,
    });
    expect(payload.sub).toBeTruthy();
  });
});

describe("Scope/claims model: profile and email claims are scope-gated", () => {
  it("includes name/email/picture from the userinfo endpoint when profile+email scope was granted", async () => {
    const { agent, tokenRes } = await authorizeAndExchange("openid profile email");

    const userinfo = await agent
      .get("/oidc/me")
      .set("Authorization", `Bearer ${tokenRes.body.access_token}`);

    expect(userinfo.status).toBe(200);
    expect(userinfo.body.email).toBe(TEST_EMAIL);
    expect(userinfo.body.email_verified).toBe(true);
    expect(userinfo.body.name).toBe("E2E Test User");
    expect(userinfo.body.picture).toBe("https://example.com/avatar.png");
  });

  it("omits name/email/picture from userinfo when only the bare openid scope was granted", async () => {
    const { agent, tokenRes } = await authorizeAndExchange("openid");

    const userinfo = await agent
      .get("/oidc/me")
      .set("Authorization", `Bearer ${tokenRes.body.access_token}`);

    expect(userinfo.status).toBe(200);
    expect(userinfo.body.sub).toBeTruthy();
    expect(userinfo.body.email).toBeUndefined();
    expect(userinfo.body.name).toBeUndefined();
    expect(userinfo.body.picture).toBeUndefined();
  });
});

describe("Refresh token rotation with reuse detection", () => {
  it("rotates the refresh token on use, and revokes the whole grant if an old one is replayed", async () => {
    const { agent, tokenRes } = await authorizeAndExchange("openid offline_access");
    const firstRefreshToken = tokenRes.body.refresh_token;
    expect(firstRefreshToken).toBeTruthy();

    const secondRes = await agent
      .post("/oidc/token")
      .type("form")
      .send({ grant_type: "refresh_token", refresh_token: firstRefreshToken, client_id: "e2e-public-client" });

    expect(secondRes.status).toBe(200);
    const secondRefreshToken = secondRes.body.refresh_token;
    expect(secondRefreshToken).toBeTruthy();
    expect(secondRefreshToken).not.toBe(firstRefreshToken);

    // Replaying the now-consumed first refresh token must fail...
    const replayRes = await agent
      .post("/oidc/token")
      .type("form")
      .send({ grant_type: "refresh_token", refresh_token: firstRefreshToken, client_id: "e2e-public-client" });
    expect(replayRes.status).toBe(400);
    expect(replayRes.body.error).toBe("invalid_grant");

    // ...and that failure must revoke the WHOLE grant, not just the replayed
    // token — so even the legitimately-rotated second refresh token is now dead.
    const secondTryRes = await agent
      .post("/oidc/token")
      .type("form")
      .send({ grant_type: "refresh_token", refresh_token: secondRefreshToken, client_id: "e2e-public-client" });
    expect(secondTryRes.status).toBe(400);
    expect(secondTryRes.body.error).toBe("invalid_grant");
  });
});

describe("Client credentials flow for service-to-service calls", () => {
  it("issues a plain access_token with no resource indicator", async () => {
    const res = await request(app)
      .post("/oidc/token")
      .type("form")
      .auth("e2e-service-client", "e2e-service-secret")
      .send({ grant_type: "client_credentials", scope: "internal:read" });

    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeTruthy();
    expect(res.body.scope).toBe("internal:read");
  });

  it("issues a resource-scoped access_token when a registered resource indicator is requested", async () => {
    const res = await request(app)
      .post("/oidc/token")
      .type("form")
      .auth("e2e-service-client", "e2e-service-secret")
      .send({
        grant_type: "client_credentials",
        resource: INTERNAL_API_RESOURCE,
        scope: "internal:read internal:write",
      });

    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeTruthy();
    expect(res.body.scope).toBe("internal:read internal:write");
  });
});

describe("JWKS endpoint", () => {
  it("serves the configured persistent key, not an ephemeral one", async () => {
    const res = await request(app).get("/oidc/jwks");
    expect(res.status).toBe(200);
    expect(res.body.keys[0].kid).toBe(config.jwks.keys[0].kid);
  });
});

describe("Discovery document completeness", () => {
  it("advertises the endpoints and capabilities this phase actually implements", async () => {
    const res = await request(app).get("/oidc/.well-known/openid-configuration");
    expect(res.status).toBe(200);
    const doc = res.body;

    // `issuer` is our static config value, but the other endpoint URLs are
    // host-qualified using the *serving* request's host (correct koa/
    // oidc-provider behavior for reverse-proxy-friendly deployments) — which
    // won't match our static issuer host under supertest's ephemeral test
    // server, so only the path portion is meaningful to assert here.
    expect(doc.issuer).toBe(config.issuer);
    expect(new URL(doc.authorization_endpoint).pathname).toBe("/oidc/auth");
    expect(new URL(doc.token_endpoint).pathname).toBe("/oidc/token");
    expect(new URL(doc.jwks_uri).pathname).toBe("/oidc/jwks");
    expect(doc.response_types_supported).toContain("code");
    expect(doc.grant_types_supported).toEqual(
      expect.arrayContaining(["authorization_code", "refresh_token", "client_credentials"]),
    );
    expect(doc.code_challenge_methods_supported).toContain("S256");
    expect(doc.scopes_supported).toEqual(
      expect.arrayContaining(["openid", "profile", "email", "offline_access"]),
    );
    expect(doc.claims_supported).toEqual(expect.arrayContaining(["email", "name", "picture"]));
  });
});
