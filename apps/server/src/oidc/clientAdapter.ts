import type { AdapterPayload } from "oidc-provider";
import { prisma } from "../db.js";

/**
 * oidc-provider's "Client" model adapter — backed directly by our own Client
 * table (registered downstream Neko* apps) instead of the generic OidcModel
 * table, so the admin console can CRUD real columns rather than JSON blobs.
 *
 * Only `find` is implemented for real: oidc-provider only ever reads clients
 * through this adapter in our setup (writes go through Prisma directly, from
 * the admin console in Phase 8). The rest of the interface is still provided
 * — as safe no-ops — so oidc-provider doesn't crash if it ever calls them.
 */
export class ClientAdapter {
  async find(clientId: string) {
    const client = await prisma.client.findUnique({ where: { clientId } });
    if (!client) return undefined;

    // Cast: Prisma stores these as plain string[]/string columns, but
    // oidc-provider's types narrow them to specific literal unions (e.g.
    // ResponseType). The admin console (Phase 8) is the only place these
    // columns get written, so it owns keeping the values valid.
    return {
      client_id: client.clientId,
      client_secret: client.clientSecret ?? undefined,
      redirect_uris: client.redirectUris,
      response_types: client.responseTypes,
      grant_types: client.grantTypes,
      token_endpoint_auth_method: client.tokenEndpointAuthMethod,
      scope: client.scope,
    } as unknown as AdapterPayload;
  }

  async upsert() {
    // No-op: clients are managed directly via Prisma (admin console, Phase 8).
  }

  async destroy() {
    // No-op: see upsert().
  }

  async consume() {
    // No-op: Client isn't a consumable/expiring model.
  }

  async findByUserCode() {
    return undefined;
  }

  async findByUid() {
    return undefined;
  }

  async revokeByGrantId() {
    // No-op: Client isn't grant-scoped.
  }
}
