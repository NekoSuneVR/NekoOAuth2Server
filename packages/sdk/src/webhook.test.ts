import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import { parseWebhookPayload, verifyAndParseWebhook, verifyWebhookSignature } from "./webhook.js";

const SECRET = "test-webhook-secret";

function sign(body: string, secret = SECRET) {
  return `sha256=${crypto.createHmac("sha256", secret).update(body).digest("hex")}`;
}

describe("verifyWebhookSignature", () => {
  it("accepts a correctly signed body — matches the server's own signing scheme exactly", () => {
    const body = JSON.stringify({ event: "user.deleted", data: { sub: "user-123" }, timestamp: "2026-01-01T00:00:00.000Z" });
    expect(verifyWebhookSignature(body, sign(body), SECRET)).toBe(true);
  });

  it("rejects a body that was tampered with after signing", () => {
    const body = JSON.stringify({ event: "user.deleted", data: { sub: "user-123" } });
    const signature = sign(body);
    const tampered = JSON.stringify({ event: "user.deleted", data: { sub: "someone-else" } });
    expect(verifyWebhookSignature(tampered, signature, SECRET)).toBe(false);
  });

  it("rejects a signature produced with the wrong secret", () => {
    const body = JSON.stringify({ event: "user.deleted", data: { sub: "user-123" } });
    expect(verifyWebhookSignature(body, sign(body, "wrong-secret"), SECRET)).toBe(false);
  });

  it("rejects a missing signature header", () => {
    expect(verifyWebhookSignature("{}", undefined, SECRET)).toBe(false);
    expect(verifyWebhookSignature("{}", null, SECRET)).toBe(false);
  });

  it("rejects a malformed signature header (no scheme prefix)", () => {
    expect(verifyWebhookSignature("{}", "not-a-real-signature", SECRET)).toBe(false);
  });

  it("works against a real Buffer, not just a string", () => {
    const body = Buffer.from(JSON.stringify({ event: "user.deleted", data: { sub: "user-123" } }));
    expect(verifyWebhookSignature(body, sign(body.toString()), SECRET)).toBe(true);
  });
});

describe("parseWebhookPayload / verifyAndParseWebhook", () => {
  it("parses a valid event payload", () => {
    const body = JSON.stringify({ event: "user.deleted", data: { sub: "user-123" }, timestamp: "2026-01-01T00:00:00.000Z" });
    const parsed = parseWebhookPayload(body);
    expect(parsed.event).toBe("user.deleted");
    expect(parsed.data).toEqual({ sub: "user-123" });
  });

  it("verifyAndParseWebhook returns the parsed event when the signature is valid", () => {
    const body = JSON.stringify({ event: "user.deleted", data: { sub: "user-123" }, timestamp: "2026-01-01T00:00:00.000Z" });
    const event = verifyAndParseWebhook(body, sign(body), SECRET);
    expect(event.data).toEqual({ sub: "user-123" });
  });

  it("verifyAndParseWebhook throws when the signature is invalid", () => {
    const body = JSON.stringify({ event: "user.deleted", data: { sub: "user-123" } });
    expect(() => verifyAndParseWebhook(body, "sha256=deadbeef", SECRET)).toThrow(/invalid webhook signature/);
  });
});
