/**
 * Everything downstream of "I have a rendered subject/html, send it" goes
 * through this interface — v1 only ships an SMTP implementation, but a
 * SendGrid/Mailgun/HTTP-based sender (Phase 6's stated future work) is a new
 * implementation of this same interface, not a redesign.
 */
export interface EmailSender {
  send(message: { to: string; subject: string; html: string }): Promise<void>;
}

export const EMAIL_USAGE_TYPES = [
  "SignIn",
  "Register",
  "ForgotPassword",
  "OrganizationInvitation",
  "Generic",
  "UserPermissionValidation",
  "BindNewIdentifier",
  "MfaVerification",
  "BindMfa",
] as const;

export type EmailUsageType = (typeof EMAIL_USAGE_TYPES)[number];

export function isEmailUsageType(value: string): value is EmailUsageType {
  return (EMAIL_USAGE_TYPES as readonly string[]).includes(value);
}
