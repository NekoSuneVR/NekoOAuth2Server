import bcrypt from "bcryptjs";
import request from "supertest";
import { beforeAll, describe, expect, it } from "vitest";

/**
 * A dedicated file rather than adding this to the main suite: sets a tiny
 * rate limit via env var *before* dynamically importing the app (a static
 * import would already have constructed the limiters with the default,
 * generous production limits — see src/security/rateLimit.ts). Isolating it
 * here means the rest of the test suite keeps exercising the app under
 * realistic, generous limits that won't spuriously 429 a normal test flow.
 */
process.env.RATE_LIMIT_LOGIN_MAX = "3";

const { app } = await import("../app.js");
const { prisma } = await import("../db.js");

const TEST_EMAIL = "rate-limit-test@example.com";
const TEST_PASSWORD = "correct-horse-battery-staple";

beforeAll(async () => {
  await prisma.user.upsert({
    where: { primaryEmail: TEST_EMAIL },
    update: {},
    create: {
      primaryEmail: TEST_EMAIL,
      emailVerified: true,
      passwordHash: await bcrypt.hash(TEST_PASSWORD, 10),
    },
  });
});

describe("Rate limiting on /account/login", () => {
  it("allows requests under the limit, then rejects with 429 once exceeded", async () => {
    const agent = request.agent(app);

    for (let i = 0; i < 3; i++) {
      const res = await agent.post("/account/login").type("form").send({ email: TEST_EMAIL, password: "wrong" });
      expect(res.status).toBe(401);
    }

    const limited = await agent.post("/account/login").type("form").send({ email: TEST_EMAIL, password: "wrong" });
    expect(limited.status).toBe(429);
    expect(limited.body.error).toBe("too_many_requests");
  });

  it("still rate-limits even a correct login once the window is exhausted", async () => {
    const agent = request.agent(app);
    for (let i = 0; i < 3; i++) {
      await agent.post("/account/login").type("form").send({ email: TEST_EMAIL, password: "wrong" });
    }

    const res = await agent
      .post("/account/login")
      .type("form")
      .send({ email: TEST_EMAIL, password: TEST_PASSWORD });
    expect(res.status).toBe(429);
  });
});
