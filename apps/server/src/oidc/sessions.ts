import { prisma } from "../db.js";

export interface ActiveGrantSummary {
  grantId: string;
  clientId: string;
  clientName: string;
  scopes: string[];
}

interface GrantPayload {
  accountId?: string;
  clientId?: string;
  openid?: { scope?: string };
}

/** "Apps you're currently signed into" — one row per Grant, not per token (a client can hold several tokens under one grant). */
export async function listActiveGrantsForUser(userId: string): Promise<ActiveGrantSummary[]> {
  const grants = await prisma.oidcModel.findMany({
    where: { type: "Grant", payload: { path: ["accountId"], equals: userId } },
  });

  const results: ActiveGrantSummary[] = [];
  for (const grant of grants) {
    const payload = grant.payload as GrantPayload;
    if (!payload.clientId) continue;
    const client = await prisma.client.findUnique({ where: { clientId: payload.clientId } });
    results.push({
      grantId: grant.id,
      clientId: payload.clientId,
      clientName: client?.name ?? payload.clientId,
      scopes: payload.openid?.scope ? payload.openid.scope.split(" ") : [],
    });
  }
  return results;
}

/** Revokes one grant (and every token/code issued under it) — "sign this one app out," not everything. */
export async function revokeGrantForUser(userId: string, grantId: string): Promise<boolean> {
  const grant = await prisma.oidcModel.findUnique({ where: { type_id: { type: "Grant", id: grantId } } });
  if (!grant) return false;
  const payload = grant.payload as GrantPayload;
  if (payload.accountId !== userId) return false;

  await prisma.oidcModel.deleteMany({ where: { grantId } });
  await prisma.oidcModel.deleteMany({ where: { type: "Grant", id: grantId } });
  return true;
}

/**
 * Revokes every active grant (and the tokens/codes issued under it) plus any
 * live browser SSO session for this account — used by both self-service
 * account deletion and the account portal's "log out everywhere."
 */
export async function revokeAllOidcStateForUser(userId: string): Promise<void> {
  const grants = await prisma.oidcModel.findMany({
    where: { type: "Grant", payload: { path: ["accountId"], equals: userId } },
    select: { id: true },
  });

  for (const grant of grants) {
    await prisma.oidcModel.deleteMany({ where: { grantId: grant.id } });
  }
  if (grants.length > 0) {
    await prisma.oidcModel.deleteMany({ where: { type: "Grant", id: { in: grants.map((g) => g.id) } } });
  }

  await prisma.oidcModel.deleteMany({
    where: { type: "Session", payload: { path: ["accountId"], equals: userId } },
  });
}
