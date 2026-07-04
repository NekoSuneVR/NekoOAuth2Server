import { prisma } from "../db.js";
import { decryptSecret, isEncryptedSecret } from "../security/encryption.js";
import { createSmtpSender } from "./smtpSender.js";
import type { EmailSender } from "./types.js";

export const SMTP_CONFIG_ID = "default";

/**
 * Same "inject a fake, never guess at a real one" escape hatch used for the
 * VRChat bot client (src/connectors/vrchat/clientProvider.ts) — lets tests
 * exercise sendTemplatedEmail's rate-limiting/logging logic without needing a
 * real SMTP config row.
 */
let senderOverride: EmailSender | null = null;

export function setEmailSenderForTesting(sender: EmailSender | null): void {
  senderOverride = sender;
}

/**
 * Returns null (not a crash) when no SmtpConfig row exists yet — same
 * "disabled until configured" pattern as the upstream OAuth connectors.
 */
export async function getEmailSender(): Promise<EmailSender | null> {
  if (senderOverride) return senderOverride;

  const config = await prisma.smtpConfig.findUnique({ where: { id: SMTP_CONFIG_ID } });
  if (!config) return null;

  const password = config.password
    ? isEncryptedSecret(config.password)
      ? decryptSecret(config.password)
      : config.password
    : config.password;

  return createSmtpSender({ ...config, password });
}
