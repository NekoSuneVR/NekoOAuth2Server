import crypto from "node:crypto";

/**
 * Envelope encryption at rest for secrets that genuinely need to be
 * recovered in plaintext later (client secrets oidc-provider does a raw
 * comparison against, SMTP passwords, upstream connector client secrets) —
 * the thing Phase 0/6's "revisit as reversible encryption, not hashing"
 * notes were pointing at. AES-256-GCM: authenticated, so a tampered
 * ciphertext fails to decrypt rather than silently returning garbage.
 *
 * `ENCRYPTION_KEY` must be a base64-encoded 32-byte key in any real
 * deployment. Left unset, this falls back to a fixed, publicly-known,
 * clearly-insecure dev key (logged loudly) — the same "ephemeral dev
 * fallback, never for production" pattern already used for the JWKS and
 * cookie-signing secrets elsewhere in this server.
 */
const DEV_INSECURE_KEY = Buffer.from("0".repeat(64), "hex"); // 32 zero bytes — never use for anything real
const ALGORITHM = "aes-256-gcm";
const VERSION_PREFIX = "v1";

let loggedDevKeyWarning = false;

function resolveKey(): Buffer {
  const configured = process.env.ENCRYPTION_KEY;
  if (!configured) {
    if (!loggedDevKeyWarning) {
      console.warn(
        "ENCRYPTION_KEY is not set — using a fixed, publicly-known dev key to encrypt secrets at rest. " +
          "NOT SECURE FOR PRODUCTION. Generate a real one: `openssl rand -base64 32`.",
      );
      loggedDevKeyWarning = true;
    }
    return DEV_INSECURE_KEY;
  }
  const key = Buffer.from(configured, "base64");
  if (key.length !== 32) {
    throw new Error(`ENCRYPTION_KEY must decode to exactly 32 bytes (got ${key.length}) — generate with \`openssl rand -base64 32\``);
  }
  return key;
}

export function encryptSecret(plaintext: string): string {
  const key = resolveKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [VERSION_PREFIX, iv.toString("base64"), authTag.toString("base64"), ciphertext.toString("base64")].join(":");
}

export function decryptSecret(stored: string): string {
  const parts = stored.split(":");
  if (parts.length !== 4 || parts[0] !== VERSION_PREFIX) {
    throw new Error("unrecognized encrypted secret format");
  }
  const [, ivB64, authTagB64, ciphertextB64] = parts;
  const key = resolveKey();
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(authTagB64, "base64"));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(ciphertextB64, "base64")), decipher.final()]);
  return plaintext.toString("utf8");
}

/** True if the value looks like our own encrypted format, vs. legacy plaintext still in the database. */
export function isEncryptedSecret(value: string): boolean {
  return value.startsWith(`${VERSION_PREFIX}:`) && value.split(":").length === 4;
}
