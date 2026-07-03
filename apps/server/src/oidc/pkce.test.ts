import crypto from "node:crypto";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { oidcProvider } from "./provider.js";

const REDIRECT_URI = "http://localhost:3000/callback";

function pkcePair() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

beforeAll(async () => {
  const tenant = await prisma.tenant.upsert({
    where: { slug: "test-tenant" },
    update: {},
    create: { name: "Test Tenant", slug: "test-tenant" },
  });

  await prisma.client.upsert({
    where: { clientId: "pkce-test-public" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "PKCE Test Public Client",
      clientId: "pkce-test-public",
      clientSecret: null,
      isConfidential: false,
      redirectUris: [REDIRECT_URI],
      tokenEndpointAuthMethod: "none",
    },
  });

  await prisma.client.upsert({
    where: { clientId: "pkce-test-confidential" },
    update: {},
    create: {
      tenantId: tenant.id,
      name: "PKCE Test Confidential Client",
      clientId: "pkce-test-confidential",
      clientSecret: "pkce-test-secret",
      isConfidential: true,
      redirectUris: [REDIRECT_URI],
      tokenEndpointAuthMethod: "client_secret_basic",
    },
  });
});

describe("PKCE is required at the authorization endpoint for every client type", () => {
  it("rejects a public client's request with no code_challenge", async () => {
    const res = await request(oidcProvider.callback())
      .get("/auth")
      .query({
        client_id: "pkce-test-public",
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        scope: "openid",
        state: "s1",
      });

    expect(res.status).toBe(303);
    const location = new URL(res.headers.location, REDIRECT_URI);
    expect(location.searchParams.get("error")).toBe("invalid_request");
    expect(location.searchParams.get("error_description")).toMatch(/PKCE/i);
  });

  it("rejects a CONFIDENTIAL client's request with no code_challenge (stricter than the RFC 9700 default)", async () => {
    const res = await request(oidcProvider.callback())
      .get("/auth")
      .query({
        client_id: "pkce-test-confidential",
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        scope: "openid",
        state: "s2",
      });

    expect(res.status).toBe(303);
    const location = new URL(res.headers.location, REDIRECT_URI);
    expect(location.searchParams.get("error")).toBe("invalid_request");
    expect(location.searchParams.get("error_description")).toMatch(/PKCE/i);
  });

  it("does NOT reject for missing PKCE once a code_challenge is supplied", async () => {
    const { challenge } = pkcePair();
    const res = await request(oidcProvider.callback())
      .get("/auth")
      .query({
        client_id: "pkce-test-public",
        response_type: "code",
        redirect_uri: REDIRECT_URI,
        scope: "openid",
        state: "s3",
        code_challenge: challenge,
        code_challenge_method: "S256",
      });

    expect(res.status).toBe(303);
    // Proceeds to the interaction (login) step, not an error redirect back to the client.
    expect(res.headers.location).toMatch(/^\/interaction\//);
  });
});

describe("PKCE is enforced at the token endpoint (code exchange)", () => {
  async function issueCodeBoundToChallenge(clientId: string, codeChallenge: string) {
    const client = await oidcProvider.Client.find(clientId);
    if (!client) throw new Error(`test setup: client ${clientId} not found`);

    const grant = new oidcProvider.Grant({ accountId: "test-account-1", clientId });
    grant.addOIDCScope("openid");
    const grantId = await grant.save();

    const code = new oidcProvider.AuthorizationCode({
      client,
      accountId: "test-account-1",
      grantId,
      gty: "authorization_code",
      redirectUri: REDIRECT_URI,
      scope: "openid",
      codeChallenge,
      codeChallengeMethod: "S256",
    });
    return code.save();
  }

  it("rejects a code exchange with the WRONG code_verifier", async () => {
    const { challenge } = pkcePair();
    const code = await issueCodeBoundToChallenge("pkce-test-public", challenge);

    const res = await request(oidcProvider.callback())
      .post("/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: "pkce-test-public",
        code_verifier: crypto.randomBytes(32).toString("base64url"),
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
  });

  it("rejects a code exchange with NO code_verifier at all", async () => {
    const { challenge } = pkcePair();
    const code = await issueCodeBoundToChallenge("pkce-test-public", challenge);

    const res = await request(oidcProvider.callback())
      .post("/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: "pkce-test-public",
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
  });

  it("succeeds with the CORRECT code_verifier — proves the mechanism works, not just that it always errors", async () => {
    const { verifier, challenge } = pkcePair();
    const code = await issueCodeBoundToChallenge("pkce-test-public", challenge);

    const res = await request(oidcProvider.callback())
      .post("/token")
      .type("form")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        client_id: "pkce-test-public",
        code_verifier: verifier,
      });

    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeTruthy();
  });

  it("also enforces PKCE at code exchange for a CONFIDENTIAL client", async () => {
    const { challenge } = pkcePair();
    const code = await issueCodeBoundToChallenge("pkce-test-confidential", challenge);

    const res = await request(oidcProvider.callback())
      .post("/token")
      .type("form")
      .auth("pkce-test-confidential", "pkce-test-secret")
      .send({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
        code_verifier: crypto.randomBytes(32).toString("base64url"),
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
  });
});
