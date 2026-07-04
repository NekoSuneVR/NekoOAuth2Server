import type { NextFunction, Request, Response } from "express";
import { prisma } from "../db.js";
import { oidcProvider } from "../oidc/provider.js";

// Attached by requirePermission once the caller is confirmed to hold the
// required permission — every admin API handler can read `req.admin` to
// record who did it, without re-deriving it from the Authorization header
// itself. Not a global Request augmentation (that would risk colliding with
// other type declarations elsewhere) — callers cast, same pattern already
// used in packages/sdk/src/express.ts.
export interface AdminIdentity {
  userId: string;
  clientId: string;
}

export type RequestWithAdmin = Request & { admin?: AdminIdentity };

/**
 * Express middleware protecting an API route by permission, the pattern any
 * real admin API (Phase 8) follows. Roles/permissions are looked up fresh
 * against the current database on every call rather than trusted from a
 * token claim, so a revoked role takes effect immediately rather than only
 * once the token expires.
 */
export function requirePermission(permission: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith("Bearer ")) {
      res.status(401).json({ error: "invalid_token", error_description: "missing bearer token" });
      return;
    }

    const accessToken = await oidcProvider.AccessToken.find(auth.slice("Bearer ".length));
    if (!accessToken?.accountId || !accessToken.clientId) {
      res.status(401).json({ error: "invalid_token", error_description: "unknown or expired access token" });
      return;
    }

    const client = await prisma.client.findUnique({ where: { clientId: accessToken.clientId } });
    if (!client) {
      res.status(401).json({ error: "invalid_token", error_description: "unknown client" });
      return;
    }

    const userRoles = await prisma.userRole.findMany({
      where: { userId: accessToken.accountId, role: { clientId: client.id } },
      include: { role: true },
    });
    const permissions = new Set(userRoles.flatMap((ur) => ur.role.permissions));

    if (!permissions.has(permission)) {
      res.status(403).json({ error: "insufficient_permission", required: permission });
      return;
    }

    (req as RequestWithAdmin).admin = { userId: accessToken.accountId, clientId: client.id };
    next();
  };
}
