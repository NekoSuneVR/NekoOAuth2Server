import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import { generateCodeChallenge, generateCodeVerifier, generateState } from "./pkce.js";

describe("PKCE helpers", () => {
  it("generates a verifier long enough to satisfy RFC 7636 (43-128 chars)", () => {
    const verifier = generateCodeVerifier();
    expect(verifier.length).toBeGreaterThanOrEqual(43);
    expect(verifier.length).toBeLessThanOrEqual(128);
    expect(verifier).toMatch(/^[A-Za-z0-9\-_]+$/);
  });

  it("derives the S256 challenge exactly as RFC 7636 defines it", () => {
    const verifier = "test-verifier-value";
    const expected = crypto.createHash("sha256").update(verifier).digest("base64url");
    expect(generateCodeChallenge(verifier)).toBe(expected);
  });

  it("generates a different verifier every call", () => {
    const a = generateCodeVerifier();
    const b = generateCodeVerifier();
    expect(a).not.toBe(b);
  });

  it("generates a non-empty, url-safe state value", () => {
    const state = generateState();
    expect(state.length).toBeGreaterThan(0);
    expect(state).toMatch(/^[A-Za-z0-9\-_]+$/);
  });
});
