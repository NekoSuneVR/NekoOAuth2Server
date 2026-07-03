import type { NextFunction, Request, RequestHandler, Response, Router as RouterType } from "express";
import { Router } from "express";
import type { NekoAuthClient } from "./client.js";
import type { TokenSet, UserProfile } from "./types.js";
import { parseWebhookPayload, verifyWebhookSignature, type NekoWebhookEvent } from "./webhook.js";

export interface NekoSessionUser {
  sub: string;
  profile: UserProfile;
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
}

interface NekoSessionData {
  nekoPending?: { state: string; codeVerifier: string; returnTo: string };
  nekoUser?: NekoSessionUser;
}

// Deliberately not a `declare module "express-serve-static-core"` global
// augmentation — that would collide with whatever session typing the host
// app's own express-session (or equivalent) setup already provides. Instead
// we just read/write a couple of well-known keys on whatever `req.session`
// already is.
function requireSession(req: Request): NekoSessionData {
  const session = (req as Request & { session?: NekoSessionData }).session;
  if (!session) {
    throw new Error(
      "req.session is undefined — install express-session (or a compatible session middleware) " +
        "before mounting the NekoOAuth2Server auth router",
    );
  }
  return session;
}

export interface CreateExpressAuthOptions {
  /** default "/auth/login" */
  loginPath?: string;
  /** default "/auth/callback" */
  callbackPath?: string;
  /** default "/auth/logout" */
  logoutPath?: string;
  /** Where to send the browser after login/logout when no returnTo was given. Default "/". */
  defaultReturnTo?: string;
  scope?: string;
  onLoginSuccess?: (req: Request, user: NekoSessionUser, tokens: TokenSet) => void | Promise<void>;
}

/**
 * The Express half of the SDK: a router handling the login redirect, the
 * OIDC callback (code exchange + id_token verification + profile fetch), and
 * logout, storing the result on `req.session`. Pair with `requireAuth()` to
 * protect routes. Session storage itself is the host app's responsibility
 * (this mirrors how Passport doesn't ship its own session store either) —
 * most existing Neko* Express apps already have one configured.
 */
export function createExpressAuth(client: NekoAuthClient, options: CreateExpressAuthOptions = {}): RouterType {
  const loginPath = options.loginPath ?? "/auth/login";
  const callbackPath = options.callbackPath ?? "/auth/callback";
  const logoutPath = options.logoutPath ?? "/auth/logout";
  const defaultReturnTo = options.defaultReturnTo ?? "/";

  const router = Router();

  router.get(loginPath, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = requireSession(req);
      const { url, state, codeVerifier } = await client.createAuthorizationRequest({ scope: options.scope });
      const returnTo = typeof req.query.returnTo === "string" ? req.query.returnTo : defaultReturnTo;
      session.nekoPending = { state, codeVerifier, returnTo };
      res.redirect(url);
    } catch (err) {
      next(err);
    }
  });

  router.get(callbackPath, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = requireSession(req);
      const pending = session.nekoPending;
      if (!pending) {
        res.status(400).send("No pending login for this session — start at the login route again.");
        return;
      }
      delete session.nekoPending;

      if (req.query.error) {
        res.status(400).send(`Login failed: ${String(req.query.error)}`);
        return;
      }
      if (req.query.state !== pending.state) {
        res.status(400).send("Login failed: state mismatch.");
        return;
      }

      const tokens = await client.exchangeCode({ code: String(req.query.code), codeVerifier: pending.codeVerifier });
      const profile = await client.getUserInfo(tokens.accessToken);
      if (tokens.idToken) {
        // Verified for its signature/issuer/audience; `profile.sub` (from
        // the already-scope-checked userinfo endpoint) is what's actually
        // stored, so a mismatch here would be a sign the token isn't ours.
        const claims = await client.verifyIdToken(tokens.idToken);
        if (claims.sub !== profile.sub) {
          throw new Error("id_token subject does not match userinfo subject");
        }
      }

      const user: NekoSessionUser = {
        sub: profile.sub,
        profile,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresAt: tokens.expiresIn ? Date.now() + tokens.expiresIn * 1000 : undefined,
      };
      session.nekoUser = user;

      if (options.onLoginSuccess) await options.onLoginSuccess(req, user, tokens);
      res.redirect(pending.returnTo || defaultReturnTo);
    } catch (err) {
      next(err);
    }
  });

  router.get(logoutPath, (req: Request, res: Response) => {
    const session = requireSession(req);
    delete session.nekoUser;
    res.redirect(defaultReturnTo);
  });
  router.post(logoutPath, (req: Request, res: Response) => {
    const session = requireSession(req);
    delete session.nekoUser;
    res.redirect(defaultReturnTo);
  });

  return router;
}

/** Protects a route: redirects to the login route (preserving the original URL) if not signed in. */
export function requireAuth(options: { loginPath?: string } = {}): RequestHandler {
  const loginPath = options.loginPath ?? "/auth/login";
  return (req: Request, res: Response, next: NextFunction) => {
    const session = (req as Request & { session?: NekoSessionData }).session;
    if (!session?.nekoUser) {
      const returnTo = encodeURIComponent(req.originalUrl);
      res.redirect(`${loginPath}?returnTo=${returnTo}`);
      return;
    }
    (req as Request & { nekoUser?: NekoSessionUser }).nekoUser = session.nekoUser;
    next();
  };
}

/**
 * Verifies the `X-Neko-Signature` header and hands the parsed event to
 * `handler` — the receiving end of the server's `user.deleted` deletion
 * cascade (see the server repo's src/webhooks/deliver.ts). Mount this behind
 * `express.raw({ type: "application/json" })`, not `express.json()` — the
 * HMAC is computed over the exact bytes sent, and re-serialized JSON can
 * differ enough to fail verification even when the content is "the same".
 */
export function createWebhookMiddleware(
  secret: string,
  handler: (event: NekoWebhookEvent) => void | Promise<void>,
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const rawBody = req.body as unknown;
    if (!Buffer.isBuffer(rawBody)) {
      next(new Error("createWebhookMiddleware expects a raw Buffer body — mount express.raw() first"));
      return;
    }

    const signature = req.header("X-Neko-Signature");
    if (!verifyWebhookSignature(rawBody, signature, secret)) {
      res.status(401).json({ error: "invalid_signature" });
      return;
    }

    Promise.resolve(handler(parseWebhookPayload(rawBody)))
      .then(() => res.status(200).json({ ok: true }))
      .catch(next);
  };
}
