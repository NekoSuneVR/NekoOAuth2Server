import type { LookupAddress } from "node:dns";
import dns from "node:dns/promises";
import net from "node:net";

export class UnsafeWebhookUrlError extends Error {}

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true; // link-local, incl. cloud metadata endpoints
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();
  if (normalized === "::1") return true;
  if (normalized.startsWith("fe80:")) return true; // link-local
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true; // unique local (fc00::/7)
  if (normalized.startsWith("::ffff:")) return isPrivateIPv4(normalized.slice("::ffff:".length));
  return false;
}

/**
 * Reduces (does not eliminate) SSRF risk from admin-supplied webhook URLs
 * (TODO.md Phase 9) — rejects loopback/private/link-local addresses,
 * requires https except for an explicit localhost dev allowance. Called
 * both at registration time (src/admin/webhooksApi.ts) and again right
 * before each delivery attempt (src/webhooks/deliver.ts), since a hostname
 * that resolved to a public IP at registration could be repointed at an
 * internal one later (DNS rebinding) — checking again at delivery time
 * closes most of that window, though not a delivery-time-of-check-to-
 * time-of-use race against `fetch`'s own subsequent DNS resolution a moment
 * later. A fully airtight fix would pin the resolved IP and connect to it
 * directly; not done here.
 */
export async function assertSafeWebhookUrl(rawUrl: string): Promise<void> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new UnsafeWebhookUrlError("not a valid URL");
  }

  const isLocalhostDev = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocalhostDev)) {
    throw new UnsafeWebhookUrlError("webhook URLs must use https (plain http is only allowed for localhost, for local dev)");
  }

  // The explicit localhost/127.0.0.1 dev allowance above already decided
  // this is fine — it must short-circuit before the private-IP rejection
  // below, or "127.0.0.1" would immediately fail its own private-range check.
  if (isLocalhostDev) return;

  if (net.isIP(url.hostname)) {
    if (isPrivateIPv4(url.hostname) || isPrivateIPv6(url.hostname)) {
      throw new UnsafeWebhookUrlError("webhook URL resolves to a private/internal address");
    }
    return;
  }

  let addresses: LookupAddress[];
  try {
    addresses = await dns.lookup(url.hostname, { all: true });
  } catch {
    throw new UnsafeWebhookUrlError("could not resolve webhook hostname");
  }

  for (const { address, family } of addresses) {
    if (family === 4 && isPrivateIPv4(address)) {
      throw new UnsafeWebhookUrlError("webhook hostname resolves to a private/internal address");
    }
    if (family === 6 && isPrivateIPv6(address)) {
      throw new UnsafeWebhookUrlError("webhook hostname resolves to a private/internal address");
    }
  }
}
