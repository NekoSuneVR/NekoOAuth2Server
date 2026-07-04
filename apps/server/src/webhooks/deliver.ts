import crypto from "node:crypto";
import type { Prisma } from "@prisma/client";
import { recordAuditEvent } from "../audit/log.js";
import { prisma } from "../db.js";
import { assertSafeWebhookUrl, UnsafeWebhookUrlError } from "../security/ssrfGuard.js";

const MAX_ATTEMPTS = 3;
// Delay before attempt 2 and attempt 3 respectively — short and bounded
// (adds at most ~2.5s total) since deliverUserDeletedWebhook is awaited
// inline by account deletion, not queued.
const RETRY_DELAYS_MS = [500, 2000];

function sign(secret: string, payload: string): string {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Delivers one payload to one endpoint, retrying with backoff on failure
 * (TODO.md Phase 9) — every attempt gets its own WebhookDelivery row (the
 * `attempt` column distinguishes them), and the exact payload sent is
 * stored so the admin console's "resend" can replay it byte-for-byte later.
 * Re-checks the URL is still safe (src/security/ssrfGuard.ts) immediately
 * before each attempt, not just once at registration time.
 */
export async function deliverToEndpoint(
  endpoint: { id: string; url: string; secret: string },
  event: string,
  data: unknown,
): Promise<void> {
  const payload = { event, data, timestamp: new Date().toISOString() } as Prisma.InputJsonObject;
  const body = JSON.stringify(payload);
  const signature = sign(endpoint.secret, body);

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    let statusCode: number | null = null;
    let error: string | null = null;

    try {
      await assertSafeWebhookUrl(endpoint.url);
      const res = await fetch(endpoint.url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Neko-Signature": `sha256=${signature}` },
        body,
      });
      statusCode = res.status;
      if (res.ok) {
        await prisma.webhookDelivery.create({
          data: { webhookEndpointId: endpoint.id, event, payload, attempt, statusCode },
        });
        void recordAuditEvent("webhook.delivery.succeeded", {
          targetType: "WebhookEndpoint",
          targetId: endpoint.id,
          metadata: { event, attempt, statusCode },
        });
        return;
      }
      error = `non-2xx response: ${res.status}`;
    } catch (err) {
      error =
        err instanceof UnsafeWebhookUrlError
          ? `blocked by SSRF guard: ${err.message}`
          : err instanceof Error
            ? err.message
            : String(err);
    }

    await prisma.webhookDelivery.create({
      data: { webhookEndpointId: endpoint.id, event, payload, attempt, statusCode, error },
    });

    if (attempt === MAX_ATTEMPTS) {
      void recordAuditEvent("webhook.delivery.failed", {
        targetType: "WebhookEndpoint",
        targetId: endpoint.id,
        metadata: { event, attempt, error },
      });
      return;
    }
    await sleep(RETRY_DELAYS_MS[attempt - 1]);
  }
}

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

  const endpoints = await prisma.webhookEndpoint.findMany({ where: { clientId: { in: clientIds }, enabled: true } });
  if (endpoints.length === 0) return;

  await Promise.all(endpoints.map((endpoint) => deliverToEndpoint(endpoint, "user.deleted", { sub: userId })));
}
