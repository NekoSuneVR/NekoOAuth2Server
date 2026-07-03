import crypto from "node:crypto";

export interface NekoWebhookEvent<T = unknown> {
  event: string;
  data: T;
  timestamp: string;
}

export interface UserDeletedWebhookData {
  sub: string;
}

/**
 * Matches the server's own signing scheme exactly (see the server repo's
 * src/webhooks/deliver.ts): `X-Neko-Signature: sha256=<hex hmac-sha256 of
 * the raw request body>`. `rawBody` must be the exact bytes the server sent —
 * a body re-serialized after JSON parsing can differ in key order/whitespace
 * and silently fail verification, so callers must capture the raw body
 * (e.g. via `express.raw()`) before parsing it.
 */
export function verifyWebhookSignature(
  rawBody: string | Buffer,
  signatureHeader: string | undefined | null,
  secret: string,
): boolean {
  if (!signatureHeader) return false;
  const [scheme, signature] = signatureHeader.split("=");
  if (scheme !== "sha256" || !signature) return false;

  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
  const expectedBuf = Buffer.from(expected, "hex");
  const providedBuf = Buffer.from(signature, "hex");
  if (expectedBuf.length !== providedBuf.length) return false;
  return crypto.timingSafeEqual(expectedBuf, providedBuf);
}

export function parseWebhookPayload<T = unknown>(rawBody: string | Buffer): NekoWebhookEvent<T> {
  return JSON.parse(rawBody.toString()) as NekoWebhookEvent<T>;
}

/** Verifies the signature and parses in one step; throws if the signature doesn't check out. */
export function verifyAndParseWebhook<T = unknown>(
  rawBody: string | Buffer,
  signatureHeader: string | undefined | null,
  secret: string,
): NekoWebhookEvent<T> {
  if (!verifyWebhookSignature(rawBody, signatureHeader, secret)) {
    throw new Error("invalid webhook signature");
  }
  return parseWebhookPayload<T>(rawBody);
}
