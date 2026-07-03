import Provider, { errors, type KoaContextWithOIDC } from "oidc-provider";
import { config } from "../config.js";
import { prisma } from "../db.js";
import { adapterFactory } from "./adapter.js";

// A single hardcoded resource server for now, just to exercise the
// resource-indicator/client-credentials machinery end to end. A real
// registry (letting each Neko* backend register its own resource
// identifier + scopes) is follow-up work once a real service needs it.
export const INTERNAL_API_RESOURCE = "https://api.nekosunevr.co.uk/internal";

// Roles/permissions are scoped to a single Client (see schema.prisma's note)
// so this deliberately looks up ctx.oidc.client — the project the user is
// *currently* authenticating to — rather than returning every role the user
// holds anywhere. That's what makes cross-project isolation automatic rather
// than something each caller has to remember to filter for itself.
async function rolesAndPermissionsFor(userId: string, clientId: string | undefined) {
  if (!clientId) return { roles: [] as string[], permissions: [] as string[] };

  const client = await prisma.client.findUnique({ where: { clientId } });
  if (!client) return { roles: [] as string[], permissions: [] as string[] };

  const userRoles = await prisma.userRole.findMany({
    where: { userId, role: { clientId: client.id } },
    include: { role: true },
  });

  return {
    roles: userRoles.map((ur) => ur.role.name),
    permissions: [...new Set(userRoles.flatMap((ur) => ur.role.permissions))],
  };
}

async function findAccount(ctx: KoaContextWithOIDC, sub: string) {
  const user = await prisma.user.findUnique({ where: { id: sub } });
  if (!user) return undefined;

  return {
    accountId: user.id,
    async claims(_use: string, scope: string) {
      const claims: { sub: string; [key: string]: unknown } = {
        sub: user.id,
        email: user.primaryEmail ?? undefined,
        email_verified: user.emailVerified,
        name: user.displayName ?? undefined,
        picture: user.avatarUrl ?? undefined,
      };

      if (scope.split(" ").includes("roles")) {
        const { roles, permissions } = await rolesAndPermissionsFor(user.id, ctx.oidc?.client?.clientId);
        claims.roles = roles;
        claims.permissions = permissions;
      }

      return claims;
    },
  };
}

export const oidcProvider = new Provider(config.issuer, {
  adapter: adapterFactory,
  // Falls back to an ephemeral dev keystore (logged as "NOT SECURE FOR
  // PRODUCTION", regenerated every restart) when JWKS isn't set — see
  // scripts/generate-jwks.ts and config.ts for the real deployment path.
  jwks: config.jwks,
  cookies: {
    keys: [process.env.COOKIE_SECRET ?? "dev-insecure-cookie-secret-change-me"],
  },
  findAccount,
  // `pkce` is a top-level Configuration key, not a `features` flag — confirmed
  // against the installed package's own source (lib/helpers/defaults.js).
  pkce: {
    // Require PKCE from every client, including confidential ones — not
    // just the public-client default RFC 9700 already mandates. This is a
    // policy about clients connecting to *this* server; it says nothing
    // about the upstream connectors this server acts as a client to in
    // Phase 4 (see TODO.md's note there).
    required: () => true,
  },
  claims: {
    openid: ["sub"],
    profile: ["name", "picture"],
    email: ["email", "email_verified"],
    // `roles` becomes a recognized scope automatically (any key here does —
    // oidc-provider's collectScopes() adds claim-defined scope names to the
    // recognized set on its own, unlike the plain `scopes` array below).
    roles: ["roles", "permissions"],
  },
  // Non-claim scope names the server recognizes at all — a separate concern
  // from which of them a given resource server actually grants (that's
  // `getResourceServerInfo`'s `scope` return value below). A client's own
  // `scope` metadata is validated against this list, so resource-specific
  // scopes need to be registered here too, not just returned per-resource.
  // This *replaces*, not extends, the library default (`['openid',
  // 'offline_access']`) — omitting them here silently disables the
  // refresh_token grant entirely, since oidc-provider only enables it when
  // 'offline_access' is present in this exact list. Found by hitting that
  // failure for real, not by reading the docs closely enough the first time.
  scopes: ["openid", "offline_access", "internal:read", "internal:write"],
  features: {
    clientCredentials: { enabled: true },
    resourceIndicators: {
      enabled: true,
      getResourceServerInfo: async (_ctx, resourceIndicator) => {
        if (resourceIndicator === INTERNAL_API_RESOURCE) {
          return { scope: "internal:read internal:write" };
        }
        throw new errors.InvalidTarget();
      },
    },
  },
});

oidcProvider.on("server_error", (_ctx, err) => {
  console.error("oidc-provider server_error:", err);
});
