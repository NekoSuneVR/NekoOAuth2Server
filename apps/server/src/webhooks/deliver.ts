import crypto from "node:crypto";
import { prisma } from "../db.js";

/**
 * Notifies every downstream app this user actually has a relationship with —
 * per TODO.md Phase 0's decision that deletion here has to mean deletion
 * everywhere this identity has been shared. `ClientConsent` is the
 * structured signal for "this client has definitely authenticated this
 * user" (LinkedIdentity is about upstream providers *we* consume, not which
 * of our own clients know this user).
 */
export async function deliverUserDeletedWebhook(userId: string): Promise<void> {
  const consents = await prisma.clientConsent.findMany({
    where: { userId },
    select: { clientId: true },
  });
  const clientIds = [...new Set(consents.map((c) => c.clientId))];
  if (clientIds.length === 0) return;

  const endpoints = await prisma.webhookEndpoint.findMany({ where: { clientId: { in: clientIds } } });
  if (endpoints.length === 0) return;

  const payload = JSON.stringify({
    event: "user.deleted",
    data: { sub: userId },
    timestamp: new Date().toISOString(),
  });

  await Promise.all(
    endpoints.map(async (endpoint) => {
      const signature = crypto.createHmac("sha256", endpoint.secret).update(payload).digest("hex");
      let statusCode: number | null = null;
      let error: string | null = null;

      try {
        const res = await fetch(endpoint.url, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Neko-Signature": `sha256=${signature}` },
          body: payload,
        });
        statusCode = res.status;
      } catch (err) {
        error = err instanceof Error ? err.message : String(err);
      }

      await prisma.webhookDelivery.create({
        data: { webhookEndpointId: endpoint.id, event: "user.deleted", statusCode, error },
      });
    }),
  );
}
