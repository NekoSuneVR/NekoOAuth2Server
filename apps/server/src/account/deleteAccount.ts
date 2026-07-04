import { recordAuditEvent } from "../audit/log.js";
import { prisma } from "../db.js";
import { revokeAllOidcStateForUser } from "../oidc/sessions.js";
import { deliverUserDeletedWebhook } from "../webhooks/deliver.js";

/**
 * Deletes a user's own account (self-service). Order matters: the deletion
 * webhook fires *before* anything is removed, since it reads ClientConsent
 * to know who to notify — deleting first would make that lookup useless.
 * `revokeAllOidcStateForUser` (src/oidc/sessions.ts) is shared with the
 * account portal's "log out everywhere" — deleting the User row alone would
 * leave existing access/refresh tokens and cookie sessions valid until they
 * naturally expire, which isn't really "deleted."
 */
export async function deleteUserAccount(userId: string, actor?: { userId?: string; clientId?: string }): Promise<void> {
  await deliverUserDeletedWebhook(userId);
  await revokeAllOidcStateForUser(userId);

  await prisma.$transaction([
    prisma.userRole.deleteMany({ where: { userId } }),
    prisma.linkedIdentity.deleteMany({ where: { userId } }),
    prisma.clientConsent.deleteMany({ where: { userId } }),
    prisma.user.delete({ where: { id: userId } }),
  ]);

  // Logged after the row is gone (not before). Defaults actorUserId to the
  // deleted user itself (self-service deletion); an admin-triggered deletion
  // passes its own identity as `actor` so the trail shows who really did it.
  void recordAuditEvent("account.deleted", {
    actorUserId: actor?.userId ?? userId,
    actorClientId: actor?.clientId,
    targetType: "User",
    targetId: userId,
    metadata: actor ? { deletedByAdmin: true } : undefined,
  });
}
