import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { sendTemplatedEmail } from "./sendEmail.js";
import { setEmailSenderForTesting } from "./senderProvider.js";
import type { EmailSender } from "./types.js";

function fakeSender() {
  const sent: { to: string; subject: string; html: string }[] = [];
  const sender: EmailSender = {
    async send(message) {
      sent.push(message);
    },
  };
  return { sender, sent };
}

beforeAll(async () => {
  await prisma.emailTemplate.upsert({
    where: { usageType: "SignIn" },
    update: { subject: "Your code: {{code}}", content: "<p>Code: {{code}}</p>" },
    create: { usageType: "SignIn", subject: "Your code: {{code}}", content: "<p>Code: {{code}}</p>" },
  });
});

afterEach(() => {
  setEmailSenderForTesting(null);
});

describe("sendTemplatedEmail", () => {
  it("renders the template, sends via the configured sender, and logs a success row", async () => {
    const { sender, sent } = fakeSender();
    setEmailSenderForTesting(sender);

    const result = await sendTemplatedEmail("SignIn", "send-success@example.com", { code: "654321" });

    expect(result).toEqual({ sent: true });
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({
      to: "send-success@example.com",
      subject: "Your code: 654321",
      html: "<p>Code: 654321</p>",
    });

    const logs = await prisma.emailLog.findMany({ where: { toAddress: "send-success@example.com" } });
    expect(logs).toHaveLength(1);
    expect(logs[0].success).toBe(true);
    expect(logs[0].usageType).toBe("SignIn");
  });

  it("fails with no_template and still logs the attempt when no template is stored for that usageType", async () => {
    const { sender } = fakeSender();
    setEmailSenderForTesting(sender);

    const result = await sendTemplatedEmail("Register", "no-template@example.com");

    expect(result).toEqual({ sent: false, reason: "no_template" });
    const logs = await prisma.emailLog.findMany({ where: { toAddress: "no-template@example.com" } });
    expect(logs).toHaveLength(1);
    expect(logs[0].success).toBe(false);
    expect(logs[0].error).toBe("no_template");
  });

  it("fails with smtp_not_configured when no sender is available and no SmtpConfig row exists", async () => {
    setEmailSenderForTesting(null);

    const result = await sendTemplatedEmail("SignIn", "not-configured@example.com");

    expect(result).toEqual({ sent: false, reason: "smtp_not_configured" });
  });

  it("logs send_failed when the sender throws", async () => {
    const sender: EmailSender = {
      async send() {
        throw new Error("connection refused");
      },
    };
    setEmailSenderForTesting(sender);

    const result = await sendTemplatedEmail("SignIn", "send-fails@example.com");

    expect(result).toEqual({ sent: false, reason: "send_failed" });
    const logs = await prisma.emailLog.findMany({ where: { toAddress: "send-fails@example.com" } });
    expect(logs[0].error).toBe("connection refused");
  });

  it("rate limits after 5 sends to the same address within the window", async () => {
    const { sender, sent } = fakeSender();
    setEmailSenderForTesting(sender);
    const to = "rate-limited@example.com";

    for (let i = 0; i < 5; i++) {
      const result = await sendTemplatedEmail("SignIn", to, { code: String(i) });
      expect(result).toEqual({ sent: true });
    }
    expect(sent).toHaveLength(5);

    const sixth = await sendTemplatedEmail("SignIn", to, { code: "999999" });
    expect(sixth).toEqual({ sent: false, reason: "rate_limited" });
    // The sender was never called a 6th time — the limit blocks before sending.
    expect(sent).toHaveLength(5);

    const logs = await prisma.emailLog.findMany({ where: { toAddress: to } });
    expect(logs).toHaveLength(6);
    expect(logs.filter((l) => l.error === "rate_limited")).toHaveLength(1);
  });
});
