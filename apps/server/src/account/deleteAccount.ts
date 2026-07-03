import { prisma } from "../db.js";
import { deliverUserDeletedWebhook } from "../webhooks/deliver.js";

/**
 * Deletes a user's own account (self-service). Order matters: the deletion
 * webhook fires *before* anything is removed, since it reads ClientConsent
 * to know who to notify — deleting first would make that lookup useless.
 */
export async function deleteUserAccount(userId: string): Promise<void> {
  await deliverUserDeletedWebhook(userId);
  await revokeAllOidcStateForUser(userId);

  await prisma.$transaction([
    prisma.userRole.deleteMany({ where: { userId } }),
    prisma.linkedIdentity.deleteMany({ where: { userId } }),
    prisma.clientConsent.deleteMany({ where: { userId } }),
    prisma.user.delete({ where: { id: userId } }),
  ]);
}

/**
 * Revokes every active grant (and the tokens/codes issued under it) plus any
 * live browser session for this account — deleting the User row alone would
 * leave existing access/refresh tokens and cookie sessions still valid until
 * they naturally expire, which isn't really "deleted."
 */
async function revokeAllOidcStateForUser(userId: string): Promise<void> {
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
