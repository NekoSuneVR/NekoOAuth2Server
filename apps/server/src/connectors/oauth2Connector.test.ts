import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createOAuth2Connector } from "./oauth2Connector.js";
import { generatePkcePair } from "./pkce.js";

/**
 * A real, locally-listening HTTP server standing in for a third-party OAuth2
 * provider (no real Discord/Roblox/etc. credentials exist in this sandbox).
 * The connector under test makes genuine HTTP requests to it — this proves
 * the connector's request construction and response parsing are correct,
 * independent of any specific real provider's availability.
 */
let server: http.Server;
let baseUrl: string;
let lastTokenRequestBody = "";
let lastUserInfoAuthHeader: string | undefined;
let lastTokenRequestAuthHeader: string | undefined;

beforeAll(async () => {
  server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");

    if (url.pathname === "/authorize") {
      const redirectUri = url.searchParams.get("redirect_uri")!;
      const state = url.searchParams.get("state")!;
      const dest = new URL(redirectUri);
      dest.searchParams.set("code", "mock-auth-code");
      dest.searchParams.set("state", state);
      res.writeHead(302, { Location: dest.toString() });
      res.end();
      return;
    }

    if (url.pathname === "/token" && req.method === "POST") {
      let raw = "";
      req.on("data", (chunk) => { raw += chunk; });
      req.on("end", () => {
        lastTokenRequestBody = raw;
        lastTokenRequestAuthHeader = req.headers.authorization;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ access_token: "mock-access-token", refresh_token: "mock-refresh-token", expires_in: 3600 }));
      });
      return;
    }

    if (url.pathname === "/userinfo") {
      lastUserInfoAuthHeader = req.headers.authorization;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: "mock-user-1", username: "mockuser", email: "mock@example.com" }));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(() => {
  server.close();
});

describe("generic OAuth2 connector", () => {
  it("builds an authorization URL with the standard params, no PKCE when unsupported", () => {
    const connector = createOAuth2Connector({
      id: "mock",
      clientId: "client-1",
      authorizationEndpoint: `${baseUrl}/authorize`,
      tokenEndpoint: `${baseUrl}/token`,
      userInfoEndpoint: `${baseUrl}/userinfo`,
      scope: "identify",
      pkce: "unsupported",
      mapUserInfo: (raw) => raw as never,
    });

    const uri = new URL(connector.getAuthorizationUri({ state: "s1", redirectUri: "http://cb/x" }));
    expect(uri.searchParams.get("response_type")).toBe("code");
    expect(uri.searchParams.get("client_id")).toBe("client-1");
    expect(uri.searchParams.get("redirect_uri")).toBe("http://cb/x");
    expect(uri.searchParams.get("scope")).toBe("identify");
    expect(uri.searchParams.get("state")).toBe("s1");
    expect(uri.searchParams.has("code_challenge")).toBe(false);
  });

  it("adds a correct S256 code_challenge when PKCE is required", () => {
    const connector = createOAuth2Connector({
      id: "mock-pkce",
      clientId: "client-1",
      authorizationEndpoint: `${baseUrl}/authorize`,
      tokenEndpoint: `${baseUrl}/token`,
      userInfoEndpoint: `${baseUrl}/userinfo`,
      scope: "identify",
      pkce: "required",
      mapUserInfo: (raw) => raw as never,
    });

    const { verifier, challenge } = generatePkcePair();
    const uri = new URL(connector.getAuthorizationUri({ state: "s1", redirectUri: "http://cb/x", codeVerifier: verifier }));
    expect(uri.searchParams.get("code_challenge")).toBe(challenge);
    expect(uri.searchParams.get("code_challenge_method")).toBe("S256");
  });

  it("throws building the authorization URL if PKCE is required but no verifier is given", () => {
    const connector = createOAuth2Connector({
      id: "mock-pkce-required",
      clientId: "client-1",
      authorizationEndpoint: `${baseUrl}/authorize`,
      tokenEndpoint: `${baseUrl}/token`,
      userInfoEndpoint: `${baseUrl}/userinfo`,
      scope: "identify",
      pkce: "required",
      mapUserInfo: (raw) => raw as never,
    });

    expect(() => connector.getAuthorizationUri({ state: "s1", redirectUri: "http://cb/x" })).toThrow(/requires PKCE/);
  });

  it("throws if PKCE is unsupported but a verifier is given anyway", () => {
    const connector = createOAuth2Connector({
      id: "mock-pkce-unsupported",
      clientId: "client-1",
      authorizationEndpoint: `${baseUrl}/authorize`,
      tokenEndpoint: `${baseUrl}/token`,
      userInfoEndpoint: `${baseUrl}/userinfo`,
      scope: "identify",
      pkce: "unsupported",
      mapUserInfo: (raw) => raw as never,
    });

    expect(() => connector.getAuthorizationUri({ state: "s1", redirectUri: "http://cb/x", codeVerifier: "x" })).toThrow(
      /does not support PKCE/,
    );
  });

  it("exchanges a code for real tokens over real HTTP and maps userinfo correctly", async () => {
    const connector = createOAuth2Connector({
      id: "mock",
      clientId: "client-1",
      clientSecret: "secret-1",
      authorizationEndpoint: `${baseUrl}/authorize`,
      tokenEndpoint: `${baseUrl}/token`,
      userInfoEndpoint: `${baseUrl}/userinfo`,
      scope: "identify email",
      pkce: "required",
      mapUserInfo: (raw) => {
        const user = raw as { id: string; username: string; email: string };
        return { id: user.id, username: user.username, email: user.email, raw };
      },
    });

    const { verifier } = generatePkcePair();
    const tokens = await connector.exchangeCode({ code: "mock-auth-code", redirectUri: "http://cb/x", codeVerifier: verifier });

    expect(tokens.accessToken).toBe("mock-access-token");
    expect(tokens.refreshToken).toBe("mock-refresh-token");
    expect(tokens.expiresIn).toBe(3600);

    const params = new URLSearchParams(lastTokenRequestBody);
    expect(params.get("grant_type")).toBe("authorization_code");
    expect(params.get("code")).toBe("mock-auth-code");
    expect(params.get("code_verifier")).toBe(verifier);
    expect(params.get("client_id")).toBe("client-1");
    expect(params.get("client_secret")).toBe("secret-1");

    const info = await connector.getUserInfo(tokens);
    expect(info.id).toBe("mock-user-1");
    expect(info.username).toBe("mockuser");
    expect(info.email).toBe("mock@example.com");
    expect(lastUserInfoAuthHeader).toBe("Bearer mock-access-token");
  });

  it("sends Basic auth instead of a body client_secret when tokenAuthMethod is client_secret_basic", async () => {
    const connector = createOAuth2Connector({
      id: "mock-basic",
      clientId: "client-2",
      clientSecret: "secret-2",
      authorizationEndpoint: `${baseUrl}/authorize`,
      tokenEndpoint: `${baseUrl}/token`,
      userInfoEndpoint: `${baseUrl}/userinfo`,
      scope: "identify",
      pkce: "unsupported",
      tokenAuthMethod: "client_secret_basic",
      mapUserInfo: (raw) => raw as never,
    });

    await connector.exchangeCode({ code: "mock-auth-code", redirectUri: "http://cb/x" });
    const params = new URLSearchParams(lastTokenRequestBody);
    expect(params.has("client_secret")).toBe(false);
    expect(lastTokenRequestAuthHeader).toBe(`Basic ${Buffer.from("client-2:secret-2").toString("base64")}`);
  });
});
