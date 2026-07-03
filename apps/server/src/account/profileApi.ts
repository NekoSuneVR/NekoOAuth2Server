import { Router } from "express";
import { prisma } from "../db.js";
import { oidcProvider } from "../oidc/provider.js";

export const profileApiRouter = Router();

/**
 * Lets a downstream app update the shared profile fields it's been granted
 * scope for — the write-side counterpart to reading them via the userinfo
 * endpoint (`/oidc/me`, already scope-filtered since Phase 2). Only fields
 * covered by the access token's own granted scope can be changed; a token
 * with just `email` can't touch `name`/`picture` and vice versa.
 */
profileApiRouter.patch("/", async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) {
    res.status(401).json({ error: "invalid_token", error_description: "missing bearer token" });
    return;
  }

  const accessToken = await oidcProvider.AccessToken.find(auth.slice("Bearer ".length));
  if (!accessToken?.accountId) {
    res.status(401).json({ error: "invalid_token", error_description: "unknown or expired access token" });
    return;
  }

  const grantedScopes = new Set((accessToken.scope ?? "").split(" "));
  const body = req.body as { name?: unknown; picture?: unknown; email?: unknown };
  const data: { displayName?: string; avatarUrl?: string; primaryEmail?: string; emailVerified?: boolean } = {};

  if (body.name !== undefined) {
    if (!grantedScopes.has("profile")) {
      res.status(403).json({ error: "insufficient_scope", required: "profile" });
      return;
    }
    data.displayName = String(body.name);
  }

  if (body.picture !== undefined) {
    if (!grantedScopes.has("profile")) {
      res.status(403).json({ error: "insufficient_scope", required: "profile" });
      return;
    }
    data.avatarUrl = String(body.picture);
  }

  if (body.email !== undefined) {
    if (!grantedScopes.has("email")) {
      res.status(403).json({ error: "insufficient_scope", required: "email" });
      return;
    }
    data.primaryEmail = String(body.email);
    data.emailVerified = false;
  }

  const user = await prisma.user.update({ where: { id: accessToken.accountId }, data });
  res.json({
    sub: user.id,
    name: user.displayName ?? undefined,
    picture: user.avatarUrl ?? undefined,
    email: user.primaryEmail ?? undefined,
    email_verified: user.emailVerified,
  });
});
