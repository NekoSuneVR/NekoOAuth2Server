import crypto from "node:crypto";
import http, { type Server } from "node:http";
import type { AddressInfo } from "node:net";
import * as jose from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createNekoAuthClient } from "./client.js";

/**
 * A local, real HTTP OIDC-ish server standing in for NekoOAuth2Server itself —
 * same "mock external services with a real local server" pattern the server
 * repo's own oauth2Connector.test.ts uses, not a mock of `fetch`/`jose`. Runs
 * a real discovery document, a real JWKS endpoint, and a real signed
 * (RS256) id_token, so the SDK's own signature/issuer/audience verification
 * is genuinely exercised, not bypassed.
 */
describe("NekoAuthClient, against a real local mock OIDC server", () => {
  let server: Server;
  let baseUrl: string;
  let keyPair: jose.GenerateKeyPairResult<jose.KeyLike>;
  const kid = "test-key-1";
  const clientId = "test-client";
  const redirectUri = "http://localhost:3000/callback";

  // authorization code -> the PKCE challenge it was issued for
  const issuedCodes = new Map<string, { codeChallenge: string; sub: string }>();
  let issuedRefreshToken: string | undefined;

  async function signIdToken(sub: string) {
    return new jose.SignJWT({ sub })
      .setProtectedHeader({ alg: "RS256", kid })
      .setIssuer(baseUrl)
      .setAudience(clientId)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(keyPair.privateKey);
  }

  beforeAll(async () => {
    keyPair = await jose.generateKeyPair("RS256");

    server = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://localhost");

      if (url.pathname === "/.well-known/openid-configuration") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            issuer: baseUrl,
            authorization_endpoint: `${baseUrl}/authorize`,
            token_endpoint: `${baseUrl}/token`,
            userinfo_endpoint: `${baseUrl}/userinfo`,
            jwks_uri: `${baseUrl}/jwks`,
          }),
        );
        return;
      }

      if (url.pathname === "/jwks") {
        jose.exportJWK(keyPair.publicKey).then((jwk) => {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ keys: [{ ...jwk, kid, use: "sig", alg: "RS256" }] }));
        });
        return;
      }

      if (url.pathname === "/token" && req.method === "POST") {
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", async () => {
          const params = new URLSearchParams(body);
          const grantType = params.get("grant_type");

          if (grantType === "authorization_code") {
            const code = params.get("code") ?? "";
            const verifier = params.get("code_verifier") ?? "";
            const issued = issuedCodes.get(code);
            if (!issued) {
              res.writeHead(400, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "invalid_grant", error_description: "unknown code" }));
              return;
            }
            const computedChallenge = crypto.createHash("sha256").update(verifier).digest("base64url");
            if (computedChallenge !== issued.codeChallenge) {
              res.writeHead(400, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "invalid_grant", error_description: "PKCE verification failed" }));
              return;
            }
            issuedCodes.delete(code);
            issuedRefreshToken = crypto.randomBytes(16).toString("hex");
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                access_token: `access-for-${issued.sub}`,
                id_token: await signIdToken(issued.sub),
                refresh_token: issuedRefreshToken,
                expires_in: 3600,
                token_type: "Bearer",
                scope: "openid profile email",
              }),
            );
            return;
          }

          if (grantType === "refresh_token") {
            if (params.get("refresh_token") !== issuedRefreshToken) {
              res.writeHead(400, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "invalid_grant" }));
              return;
            }
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                access_token: "refreshed-access-token",
                expires_in: 3600,
                token_type: "Bearer",
              }),
            );
            return;
          }

          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "unsupported_grant_type" }));
        });
        return;
      }

      if (url.pathname === "/userinfo") {
        const auth = req.headers.authorization;
        if (auth === "Bearer access-for-test-user") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ sub: "test-user", name: "Test User", email: "test-user@example.com" }));
          return;
        }
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_token" }));
        return;
      }

      res.writeHead(404).end();
    });

    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(() => {
    server.close();
  });

  it("builds an authorization URL with mandatory PKCE and a fresh state each time", async () => {
    const client = createNekoAuthClient({ issuer: baseUrl, clientId, redirectUri });
    const first = await client.createAuthorizationRequest();
    const second = await client.createAuthorizationRequest();

    const url = new URL(first.url);
    expect(url.origin + url.pathname).toBe(`${baseUrl}/authorize`);
    expect(url.searchParams.get("client_id")).toBe(clientId);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBeTruthy();
    expect(url.searchParams.get("state")).toBe(first.state);

    expect(first.state).not.toBe(second.state);
    expect(first.codeVerifier).not.toBe(second.codeVerifier);
  });

  it("exchanges a code for real tokens, verifies the id_token, and fetches userinfo", async () => {
    const client = createNekoAuthClient({ issuer: baseUrl, clientId, redirectUri });
    const { codeVerifier, state } = await client.createAuthorizationRequest();
    expect(state).toBeTruthy();

    const code = crypto.randomBytes(8).toString("hex");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    issuedCodes.set(code, { codeChallenge, sub: "test-user" });

    const tokens = await client.exchangeCode({ code, codeVerifier });
    expect(tokens.accessToken).toBe("access-for-test-user");
    expect(tokens.idToken).toBeTruthy();

    const claims = await client.verifyIdToken(tokens.idToken!);
    expect(claims.sub).toBe("test-user");

    const profile = await client.getUserInfo(tokens.accessToken);
    expect(profile).toEqual({ sub: "test-user", name: "Test User", email: "test-user@example.com" });
  });

  it("rejects a code exchange with the wrong code_verifier (PKCE actually enforced)", async () => {
    const client = createNekoAuthClient({ issuer: baseUrl, clientId, redirectUri });
    const { codeVerifier } = await client.createAuthorizationRequest();
    const code = crypto.randomBytes(8).toString("hex");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    issuedCodes.set(code, { codeChallenge, sub: "test-user" });

    const wrongVerifier = crypto.randomBytes(32).toString("base64url");
    await expect(client.exchangeCode({ code, codeVerifier: wrongVerifier })).rejects.toThrow(/invalid_grant/);
  });

  it("rejects a forged id_token signed by an unrelated key", async () => {
    const client = createNekoAuthClient({ issuer: baseUrl, clientId, redirectUri });
    const unrelatedKeyPair = await jose.generateKeyPair("RS256");
    const forged = await new jose.SignJWT({ sub: "attacker" })
      .setProtectedHeader({ alg: "RS256", kid })
      .setIssuer(baseUrl)
      .setAudience(clientId)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(unrelatedKeyPair.privateKey);

    await expect(client.verifyIdToken(forged)).rejects.toThrow();
  });

  it("rejects an id_token with the wrong audience", async () => {
    const client = createNekoAuthClient({ issuer: baseUrl, clientId, redirectUri });
    const wrongAudience = await new jose.SignJWT({ sub: "test-user" })
      .setProtectedHeader({ alg: "RS256", kid })
      .setIssuer(baseUrl)
      .setAudience("some-other-client")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(keyPair.privateKey);

    await expect(client.verifyIdToken(wrongAudience)).rejects.toThrow();
  });

  it("refreshes an access token via the refresh_token grant", async () => {
    const client = createNekoAuthClient({ issuer: baseUrl, clientId, redirectUri });
    const { codeVerifier } = await client.createAuthorizationRequest();
    const code = crypto.randomBytes(8).toString("hex");
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
    issuedCodes.set(code, { codeChallenge, sub: "test-user" });
    const tokens = await client.exchangeCode({ code, codeVerifier });

    const refreshed = await client.refreshToken(tokens.refreshToken!);
    expect(refreshed.accessToken).toBe("refreshed-access-token");
  });

  it("sends HTTP Basic client auth when a clientSecret is configured", async () => {
    let sawAuthHeader = "";
    const sniffServer = http.createServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://localhost").pathname;
      if (path === "/.well-known/openid-configuration") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            issuer: sniffBaseUrl,
            authorization_endpoint: `${sniffBaseUrl}/authorize`,
            token_endpoint: `${sniffBaseUrl}/token`,
            userinfo_endpoint: `${sniffBaseUrl}/userinfo`,
            jwks_uri: `${sniffBaseUrl}/jwks`,
          }),
        );
        return;
      }
      if (path === "/token") {
        sawAuthHeader = req.headers.authorization ?? "";
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_grant" }));
        return;
      }
      res.writeHead(404).end();
    });
    await new Promise<void>((resolve) => sniffServer.listen(0, "127.0.0.1", resolve));
    const { port } = sniffServer.address() as AddressInfo;
    const sniffBaseUrl = `http://127.0.0.1:${port}`;

    const sniffClient = createNekoAuthClient({
      issuer: sniffBaseUrl,
      clientId: "confidential-client",
      clientSecret: "shh",
      redirectUri,
    });
    await expect(sniffClient.refreshToken("whatever")).rejects.toThrow();

    const expected = `Basic ${Buffer.from("confidential-client:shh").toString("base64")}`;
    expect(sawAuthHeader).toBe(expected);
    sniffServer.close();
  });
});
