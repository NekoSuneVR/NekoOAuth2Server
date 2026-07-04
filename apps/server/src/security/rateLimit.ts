import rateLimit from "express-rate-limit";

/**
 * IP-based rate limiting on the endpoints most worth protecting against
 * brute force / credential stuffing (TODO.md Phase 9). Limits are
 * env-configurable with generous production defaults — tests that need to
 * actually trigger a 429 set a tiny limit via env var before importing the
 * app (see rateLimit.test.ts), rather than the whole suite running against
 * an artificially strict limit.
 *
 * Honest limitation: this uses express-rate-limit's default in-memory
 * store, keyed by `req.ip`. That's fine for a single server instance, but a
 * multi-instance deployment needs a shared store (e.g. a Redis-backed
 * store) or each instance enforces its own independent limit — not wired up
 * here since this project only runs single-instance so far. Also depends on
 * Express's `trust proxy` being configured correctly in front of a reverse
 * proxy, or `req.ip` will be the proxy's own address for every request.
 */
function limiterFor(envVar: string, defaultMax: number) {
  return rateLimit({
    windowMs: 60_000,
    limit: Number(process.env[envVar] ?? defaultMax),
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "too_many_requests" },
  });
}

export const authorizeRateLimiter = limiterFor("RATE_LIMIT_AUTHORIZE_MAX", 100);
export const tokenRateLimiter = limiterFor("RATE_LIMIT_TOKEN_MAX", 60);
export const accountLoginRateLimiter = limiterFor("RATE_LIMIT_LOGIN_MAX", 20);
