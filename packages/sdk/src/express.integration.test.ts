import net from "node:net";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import express from "express";
import session from "express-session";
import * as jose from "jose";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createNekoAuthClient } from "./client.js";
import { createExpressAuth, requireAuth, type NekoSessionUser } from "./express.js";

/**
 * The strongest test in this package: a real consumer Express app wired
 * with this SDK's middleware, talking over real HTTP to a real, live
 * instance of NekoOAuth2Server's own apps/server (same repo, imported
 * directly rather than mocked — the same "test against our own real,
 * already-proven-spec-compliant server" rationale the server repo's own
 * oidcConnector.test.ts uses). Proves the SDK is a genuine, working OIDC
 * relying party, not just correct against a hand-rolled stand-in.
 *
 * REQUIRES a real Postgres-speaking database reachable via DATABASE_URL
 * (this repo's convention during development is a scratch @electric-sql/
 * pglite instance — see the server repo's TODO.md Phase 1 for why), with
 * the schema pushed and `prisma:seed` already run (this test reuses the
 * seeded "test-public-client" / "test@example.com" fixtures rather than
 * creating its own, since packages/sdk has no Prisma access of its own).
 */
describe("SDK + Express, against a real live NekoOAuth2Server instance", () => {
  let realServer: Server;
  let realBaseUrl: string;
  let consumerApp: express.Express;

  async function getFreePort(): Promise<number> {
    return new Promise((resolve, reject) => {
      const srv = net.createServer();
      srv.listen(0, "127.0.0.1", () => {
        const port = (srv.address() as AddressInfo).port;
        srv.close(() => resolve(port));
      });
      srv.on("error", reject);
    });
  }

  beforeAll(async () => {
    const port = await getFreePort();
    const issuer = `http://127.0.0.1:${port}/oidc`;

    const keyPair = await jose.generateKeyPair("RS256");
    const privateJwk = await jose.exportJWK(keyPair.privateKey);

    process.env.PORT = String(port);
    process.env.ISSUER = issuer;
    process.env.DATABASE_URL ??= "postgresql://postgres:postgres@127.0.0.1:5433/postgres?pgbouncer=true&connection_limit=1";
    process.env.JWKS = JSON.stringify({ keys: [{ ...privateJwk, kid: "sdk-integration-test-key", use: "sig", alg: "RS256" }] });

    // Dynamic import so config.ts (which reads these env vars at module
    // load time) sees them — a static top-level import would run before
    // the assignments above.
    const { app } = await import("../../../apps/server/src/app.js");
    realServer = app.listen(port);
    realBaseUrl = `http://127.0.0.1:${port}`;

    const client = createNekoAuthClient({
      issuer,
      clientId: "test-public-client",
      redirectUri: "http://localhost:3000/callback",
      scope: "openid profile email",
    });

    consumerApp = express();
    consumerApp.use(session({ secret: "sdk-integration-test-secret", resave: false, saveUninitialized: true }));
    consumerApp.use(createExpressAuth(client, { defaultReturnTo: "/" }));
    consumerApp.get("/", (_req, res) => res.send("home"));
    consumerApp.get("/protected", requireAuth(), (req, res) => {
      const user = (req as express.Request & { nekoUser?: NekoSessionUser }).nekoUser;
      res.json({ ok: true, user });
    });
  }, 30000);

  afterAll(async () => {
    await new Promise<void>((resolve) => realServer.close(() => resolve()));
    const { prisma } = await import("../../../apps/server/src/db.js");
    await prisma.$disconnect();
  });

  it("redirects an unauthenticated request to login, completes real OIDC login, and then allows access", async () => {
    const consumerAgent = request.agent(consumerApp);
    const serverAgent = request.agent(realBaseUrl);

    // 1. Protected route bounces to the SDK's own login route, preserving returnTo.
    let res = await consumerAgent.get("/protected");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/auth/login?returnTo=%2Fprotected");

    // 2. The SDK's login route redirects to the REAL server's authorize endpoint.
    res = await consumerAgent.get(res.headers.location);
    expect(res.status).toBe(302);
    const authorizeUrl = new URL(res.headers.location);
    expect(authorizeUrl.origin).toBe(realBaseUrl);

    // 3. Drive the real server's authorize -> login -> consent flow for real,
    // over HTTP, the same way a browser would (adapted from the server
    // repo's own testSupport/httpAuthFlow.ts, just against a live TCP
    // server instead of an in-process app). oidc-provider's own redirects
    // are host-qualified absolute URLs, not relative paths — they have to
    // be reduced back to a path before reusing them against the agent.
    function toRequestPath(loc: string) {
      if (loc.startsWith("http://") || loc.startsWith("https://")) {
        const parsed = new URL(loc);
        return `${parsed.pathname}${parsed.search}`;
      }
      return loc;
    }

    let location: string | undefined = authorizeUrl.pathname + authorizeUrl.search;
    let hops = 0;
    while (location && !location.startsWith("http://localhost:3000/callback") && hops < 10) {
      hops += 1;
      const path = toRequestPath(location);
      if (path.includes("/interaction/")) {
        const page = await serverAgent.get(path);
        const uid = path.split("/interaction/")[1]?.split("/")[0];
        if (page.text.includes("Sign in")) {
          const loginRes = await serverAgent
            .post(`/oidc/interaction/${uid}/login`)
            .type("form")
            .send({ email: "test@example.com", password: "correct-horse-battery-staple" });
          location = loginRes.headers.location;
        } else {
          const confirmRes = await serverAgent.post(`/oidc/interaction/${uid}/confirm`).type("form").send({});
          location = confirmRes.headers.location;
        }
      } else {
        const hopRes = await serverAgent.get(path);
        location = hopRes.headers.location;
      }
    }

    expect(location).toBeTruthy();
    expect(location!.startsWith("http://localhost:3000/callback")).toBe(true);
    const callbackUrl = new URL(location!);
    const code = callbackUrl.searchParams.get("code");
    const state = callbackUrl.searchParams.get("state");
    expect(code).toBeTruthy();

    // 4. Hand the code+state back to the CONSUMER app's callback route (the
    // SDK's own route) — it holds the session with the pending PKCE
    // verifier, and does the real server-to-server token exchange +
    // id_token verification + userinfo fetch against the real server.
    res = await consumerAgent.get(`/auth/callback?code=${code}&state=${state}`);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/protected");

    // 5. Now the protected route succeeds, with a real profile from the real server.
    res = await consumerAgent.get("/protected");
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.user.sub).toBeTruthy();
    expect(res.body.user.profile.email).toBe("test@example.com");

    // 6. Logout, and the protected route bounces to login again.
    await consumerAgent.get("/auth/logout");
    res = await consumerAgent.get("/protected");
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe("/auth/login?returnTo=%2Fprotected");
  });

  it("rejects a callback whose state doesn't match the session's pending login", async () => {
    const consumerAgent = request.agent(consumerApp);
    await consumerAgent.get("/auth/login");
    const res = await consumerAgent.get("/auth/callback?code=whatever&state=not-the-real-state");
    expect(res.status).toBe(400);
  });
});
