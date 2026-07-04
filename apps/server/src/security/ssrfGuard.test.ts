import { describe, expect, it } from "vitest";
import { assertSafeWebhookUrl, UnsafeWebhookUrlError } from "./ssrfGuard.js";

describe("assertSafeWebhookUrl", () => {
  it("accepts a normal https URL", async () => {
    await expect(assertSafeWebhookUrl("https://example.com/webhooks/neko")).resolves.toBeUndefined();
  });

  it("rejects plain http for a non-localhost host", async () => {
    await expect(assertSafeWebhookUrl("http://example.com/webhooks/neko")).rejects.toThrow(UnsafeWebhookUrlError);
  });

  it("allows plain http for localhost (dev convenience)", async () => {
    await expect(assertSafeWebhookUrl("http://localhost:3000/webhooks/neko")).resolves.toBeUndefined();
    await expect(assertSafeWebhookUrl("http://127.0.0.1:3000/webhooks/neko")).resolves.toBeUndefined();
  });

  it("allows loopback over https too (the dev allowance isn't scheme-specific)", async () => {
    await expect(assertSafeWebhookUrl("https://127.0.0.1/webhooks")).resolves.toBeUndefined();
  });

  it("rejects literal private IPv4 ranges other than the localhost allowance", async () => {
    await expect(assertSafeWebhookUrl("https://10.0.0.5/webhooks")).rejects.toThrow(UnsafeWebhookUrlError);
    await expect(assertSafeWebhookUrl("https://172.16.0.5/webhooks")).rejects.toThrow(UnsafeWebhookUrlError);
    await expect(assertSafeWebhookUrl("https://192.168.1.5/webhooks")).rejects.toThrow(UnsafeWebhookUrlError);
  });

  it("rejects the link-local range that cloud metadata endpoints live in", async () => {
    await expect(assertSafeWebhookUrl("https://169.254.169.254/latest/meta-data")).rejects.toThrow(UnsafeWebhookUrlError);
  });

  it("rejects IPv6 loopback and unique-local addresses", async () => {
    await expect(assertSafeWebhookUrl("https://[::1]/webhooks")).rejects.toThrow(UnsafeWebhookUrlError);
    await expect(assertSafeWebhookUrl("https://[fd00::1]/webhooks")).rejects.toThrow(UnsafeWebhookUrlError);
  });

  it("rejects a malformed URL", async () => {
    await expect(assertSafeWebhookUrl("not a url")).rejects.toThrow(UnsafeWebhookUrlError);
  });

  it("rejects a hostname that fails to resolve", async () => {
    await expect(assertSafeWebhookUrl("https://this-domain-should-not-resolve.invalid/webhooks")).rejects.toThrow(
      UnsafeWebhookUrlError,
    );
  });
});
