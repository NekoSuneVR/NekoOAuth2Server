import crypto from "node:crypto";
import type { Request, Response } from "express";

// A small, self-contained signed-cookie session for the self-service account
// portal — deliberately separate from oidc-provider's own internal session
// mechanism (that's for OIDC interactions between a client and this server;
// this is a person managing their own account directly, the same category
// of thing as visiting myaccount.google.com). Reuses the HMAC-signed-value
// pattern already established in connectors/state.ts rather than inventing
// a different one.
const SESSION_SECRET = process.env.COOKIE_SECRET ?? "dev-insecure-cookie-secret-change-me";
const COOKIE_NAME = "neko_account";
const MAX_AGE_MS = 24 * 60 * 60 * 1000;

function sign(userId: string): string {
  const payload = Buffer.from(JSON.stringify({ userId })).toString("base64url");
  const signature = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function verify(cookieValue: string): string | undefined {
  const [payload, signature] = cookieValue.split(".");
  if (!payload || !signature) return undefined;

  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  const expectedBuf = Buffer.from(expected);
  const actualBuf = Buffer.from(signature);
  if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
    return undefined;
  }

  try {
    return (JSON.parse(Buffer.from(payload, "base64url").toString()) as { userId: string }).userId;
  } catch {
    return undefined;
  }
}

export function setAccountSession(res: Response, userId: string): void {
  res.cookie(COOKIE_NAME, sign(userId), {
    httpOnly: true,
    sameSite: "lax",
    maxAge: MAX_AGE_MS,
  });
}

export function clearAccountSession(res: Response): void {
  res.clearCookie(COOKIE_NAME);
}

export function getAccountSessionUserId(req: Request): string | undefined {
  const raw = req.cookies?.[COOKIE_NAME];
  if (typeof raw !== "string") return undefined;
  return verify(raw);
}
