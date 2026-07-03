import { prisma } from "../db.js";
import { getEmailSender } from "./senderProvider.js";
import { renderTemplate } from "./templates.js";
import type { EmailUsageType } from "./types.js";

const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;
const RATE_LIMIT_MAX_PER_ADDRESS = 5;

export type SendResult =
  | { sent: true }
  | { sent: false; reason: "rate_limited" | "no_template" | "smtp_not_configured" | "send_failed" };

/**
 * Every attempt — sent, rate-limited, or failed — gets one EmailLog row, per
 * TODO.md Phase 6's "rate limit and log every send" item. The rate limit
 * itself is just a count of an address's own recent log rows, not a separate
 * counter to keep in sync.
 */
export async function sendTemplatedEmail(
  usageType: EmailUsageType,
  to: string,
  variables: Record<string, string> = {},
): Promise<SendResult> {
  const since = new Date(Date.now() - RATE_LIMIT_WINDOW_MS);
  const recentCount = await prisma.emailLog.count({ where: { toAddress: to, sentAt: { gte: since } } });
  if (recentCount >= RATE_LIMIT_MAX_PER_ADDRESS) {
    await prisma.emailLog.create({ data: { usageType, toAddress: to, success: false, error: "rate_limited" } });
    return { sent: false, reason: "rate_limited" };
  }

  const template = await prisma.emailTemplate.findUnique({ where: { usageType } });
  if (!template) {
    await prisma.emailLog.create({ data: { usageType, toAddress: to, success: false, error: "no_template" } });
    return { sent: false, reason: "no_template" };
  }

  const sender = await getEmailSender();
  if (!sender) {
    await prisma.emailLog.create({ data: { usageType, toAddress: to, success: false, error: "smtp_not_configured" } });
    return { sent: false, reason: "smtp_not_configured" };
  }

  const subject = renderTemplate(template.subject, variables);
  const html = renderTemplate(template.content, variables);

  try {
    await sender.send({ to, subject, html });
    await prisma.emailLog.create({ data: { usageType, toAddress: to, success: true } });
    return { sent: true };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    await prisma.emailLog.create({ data: { usageType, toAddress: to, success: false, error } });
    return { sent: false, reason: "send_failed" };
  }
}
