import nodemailer from "nodemailer";
import type { EmailSender } from "./types.js";

export interface SmtpSenderConfig {
  host: string;
  port: number;
  secure: boolean;
  username?: string | null;
  password?: string | null;
  fromAddress: string;
  fromName?: string | null;
}

export function createSmtpSender(config: SmtpSenderConfig): EmailSender {
  const transport = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: config.username ? { user: config.username, pass: config.password ?? undefined } : undefined,
  });

  const from = config.fromName ? `"${config.fromName}" <${config.fromAddress}>` : config.fromAddress;

  return {
    async send({ to, subject, html }) {
      await transport.sendMail({ from, to, subject, html });
    },
  };
}
