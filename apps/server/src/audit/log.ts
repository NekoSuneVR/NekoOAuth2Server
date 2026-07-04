import { prisma } from "../db.js";

/**
 * Real, structured coverage of login, token issuance/revocation, and admin
 * actions (TODO.md Phase 9) — not literally every internal oidc-provider
 * state transition. Token events are wired from a deliberately small,
 * documented subset of oidc-provider's own emitted events (see
 * src/oidc/provider.ts): `access_token.saved` (issued), `access_token.destroyed`
 * (revoked or naturally cleaned up — oidc-provider doesn't distinguish the
 * two in this event), and `grant.revoked` (an explicit revocation, e.g. from
 * account deletion or the /oidc/token/revocation endpoint).
 */
export type AuditEvent =
  | "login.success"
  | "login.failure"
  | "token.issued"
  | "token.revoked"
  | "account.deleted"
  | "admin.client.created"
  | "admin.client.updated"
  | "admin.client.secret_rotated"
  | "admin.user.updated"
  | "admin.role.granted"
  | "admin.role.revoked"
  | "admin.smtp_config.updated"
  | "admin.email_template.updated"
  | "admin.webhook.created"
  | "admin.webhook.updated"
  | "admin.webhook.secret_rotated"
  | "admin.webhook.deleted"
  | "admin.webhook.delivery_resent"
  | "admin.connector.created"
  | "admin.connector.updated"
  | "admin.connector.deleted"
  | "webhook.delivery.succeeded"
  | "webhook.delivery.failed"
  | "session.revoked_all";

export interface AuditEventDetails {
  actorUserId?: string;
  actorClientId?: string;
  targetType?: string;
  targetId?: string;
  /**
   * Free-form context — MUST NOT ever contain a raw secret (client secret,
   * SMTP password, webhook signing secret, access/refresh token). Callers
   * are responsible for only passing already-redacted values; there's no
   * automatic scrubbing here, since the caller is the only place that
   * actually knows which fields are sensitive.
   */
  metadata?: Record<string, unknown>;
  ipAddress?: string;
}

/**
 * Never allowed to throw into the caller's request path — an audit log
 * write failing (e.g. a transient DB hiccup) must not fail the login/admin
 * action it's describing. Logged to stderr instead.
 */
export async function recordAuditEvent(event: AuditEvent, details: AuditEventDetails = {}): Promise<void> {
  try {
    await prisma.auditLogEntry.create({
      data: {
        event,
        actorUserId: details.actorUserId,
        actorClientId: details.actorClientId,
        targetType: details.targetType,
        targetId: details.targetId,
        metadata: details.metadata as never,
        ipAddress: details.ipAddress,
      },
    });
  } catch (err) {
    console.error(`Failed to record audit event "${event}":`, err);
  }
}
