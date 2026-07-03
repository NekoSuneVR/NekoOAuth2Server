import { SMTPServer } from "smtp-server";
import { afterEach, describe, expect, it } from "vitest";
import { createSmtpSender } from "./smtpSender.js";

/**
 * Verifies the real nodemailer wiring against a real local SMTP listener
 * (the `smtp-server` package — nodemailer's own sibling test-server package)
 * rather than mocking `nodemailer` itself — the same "mock external services
 * with a real local server" pattern used for the OAuth connectors in Phase 4.
 */
describe("createSmtpSender", () => {
  let server: SMTPServer | undefined;

  afterEach(async () => {
    if (!server) return;
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
  });

  it("delivers a real message over SMTP to a local test server", async () => {
    const received: { from?: string; to: string[]; data: string }[] = [];
    let pendingFrom: string | undefined;
    let pendingTo: string[] = [];

    server = new SMTPServer({
      authOptional: true,
      disabledCommands: ["STARTTLS", "AUTH"],
      onMailFrom(address, _session, callback) {
        pendingFrom = address.address;
        callback();
      },
      onRcptTo(address, _session, callback) {
        pendingTo.push(address.address);
        callback();
      },
      onData(stream, _session, callback) {
        let data = "";
        stream.on("data", (chunk: Buffer) => {
          data += chunk.toString("utf-8");
        });
        stream.on("end", () => {
          received.push({ from: pendingFrom, to: pendingTo, data });
          pendingTo = [];
          callback();
        });
      },
    });

    const port = await new Promise<number>((resolve, reject) => {
      if (!server) throw new Error("server not initialized");
      server.on("error", reject);
      const netServer = server.listen(0, "127.0.0.1", () => {
        const addr = netServer.address();
        resolve(typeof addr === "object" && addr ? addr.port : 0);
      });
    });

    const sender = createSmtpSender({
      host: "127.0.0.1",
      port,
      secure: false,
      fromAddress: "noreply@nekosunevr.co.uk",
      fromName: "NekoSuneVR",
    });

    await sender.send({
      to: "someone@example.com",
      subject: "Your NekoSuneVR sign-in code",
      html: "<p>Your code is 123456</p>",
    });

    expect(received).toHaveLength(1);
    expect(received[0].from).toBe("noreply@nekosunevr.co.uk");
    expect(received[0].to).toEqual(["someone@example.com"]);
    expect(received[0].data).toContain("Subject: Your NekoSuneVR sign-in code");
    expect(received[0].data).toContain("123456");
    expect(received[0].data).toContain("NekoSuneVR <noreply@nekosunevr.co.uk>");
  });

  it("rejects when the server refuses the recipient", async () => {
    server = new SMTPServer({
      authOptional: true,
      disabledCommands: ["STARTTLS", "AUTH"],
      onRcptTo(_address, _session, callback) {
        callback(new Error("550 no such user"));
      },
    });

    const port = await new Promise<number>((resolve, reject) => {
      if (!server) throw new Error("server not initialized");
      server.on("error", reject);
      const netServer = server.listen(0, "127.0.0.1", () => {
        const addr = netServer.address();
        resolve(typeof addr === "object" && addr ? addr.port : 0);
      });
    });

    const sender = createSmtpSender({
      host: "127.0.0.1",
      port,
      secure: false,
      fromAddress: "noreply@nekosunevr.co.uk",
    });

    await expect(
      sender.send({ to: "rejected@example.com", subject: "Test", html: "<p>x</p>" }),
    ).rejects.toThrow();
  });
});
