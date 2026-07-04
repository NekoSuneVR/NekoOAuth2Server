import crypto from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { decryptSecret, encryptSecret, isEncryptedSecret } from "./encryption.js";

const ORIGINAL_KEY = process.env.ENCRYPTION_KEY;

afterEach(() => {
  if (ORIGINAL_KEY === undefined) delete process.env.ENCRYPTION_KEY;
  else process.env.ENCRYPTION_KEY = ORIGINAL_KEY;
});

describe("encryptSecret / decryptSecret", () => {
  it("round-trips a plaintext value", () => {
    const encrypted = encryptSecret("super-secret-value");
    expect(encrypted).not.toBe("super-secret-value");
    expect(decryptSecret(encrypted)).toBe("super-secret-value");
  });

  it("produces a different ciphertext each time (random IV)", () => {
    const a = encryptSecret("same-input");
    const b = encryptSecret("same-input");
    expect(a).not.toBe(b);
    expect(decryptSecret(a)).toBe("same-input");
    expect(decryptSecret(b)).toBe("same-input");
  });

  it("rejects a tampered ciphertext instead of silently returning garbage", () => {
    const encrypted = encryptSecret("super-secret-value");
    const parts = encrypted.split(":");
    const tamperedCiphertext = Buffer.from(parts[3], "base64");
    tamperedCiphertext[0] ^= 0xff;
    const tampered = [parts[0], parts[1], parts[2], tamperedCiphertext.toString("base64")].join(":");
    expect(() => decryptSecret(tampered)).toThrow();
  });

  it("rejects an unrecognized format", () => {
    expect(() => decryptSecret("not-an-encrypted-value")).toThrow(/unrecognized/);
  });

  it("isEncryptedSecret distinguishes encrypted values from legacy plaintext", () => {
    expect(isEncryptedSecret(encryptSecret("x"))).toBe(true);
    expect(isEncryptedSecret("plain-old-secret")).toBe(false);
  });

  describe("with a real configured ENCRYPTION_KEY", () => {
    beforeEach(() => {
      process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString("base64");
    });

    it("still round-trips correctly", () => {
      const encrypted = encryptSecret("configured-key-value");
      expect(decryptSecret(encrypted)).toBe("configured-key-value");
    });

    it("a value encrypted under one key fails to decrypt under a different one", () => {
      const encrypted = encryptSecret("value");
      process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString("base64");
      expect(() => decryptSecret(encrypted)).toThrow();
    });

    it("rejects a key that isn't exactly 32 bytes", () => {
      process.env.ENCRYPTION_KEY = Buffer.from("too-short").toString("base64");
      expect(() => encryptSecret("x")).toThrow(/32 bytes/);
    });
  });
});
