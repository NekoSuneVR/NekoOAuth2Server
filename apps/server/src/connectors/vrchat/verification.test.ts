import { describe, expect, it, vi } from "vitest";
import type { VRChatBotClient } from "./types.js";
import { generateVerificationCode, verifyByBio, verifyByFriendRequest } from "./verification.js";

/** A fake clock/sleep pair so polling-loop tests run instantly instead of waiting real minutes. */
function fakeClock(startMs = 0) {
  let current = startMs;
  const now = () => current;
  const sleep = vi.fn(async (ms: number) => {
    current += ms;
  });
  return { now, sleep };
}

describe("generateVerificationCode", () => {
  it("generates a 6-character alphanumeric code, matching SocialLinkUpOnly's format", () => {
    for (let i = 0; i < 20; i += 1) {
      const code = generateVerificationCode();
      expect(code).toMatch(/^[A-Z0-9]{6}$/);
    }
  });

  it("doesn't generate the same code every time", () => {
    const codes = new Set(Array.from({ length: 20 }, () => generateVerificationCode()));
    expect(codes.size).toBeGreaterThan(1);
  });
});

describe("verifyByBio", () => {
  it("succeeds as soon as the bio contains the code", async () => {
    const client: VRChatBotClient = {
      getUserById: vi.fn().mockResolvedValue({ id: "u1", bio: "hello world ABC123 nice to meet you" }),
      sendFriendRequest: vi.fn(),
      getFriendStatus: vi.fn(),
      deleteFriendRequest: vi.fn(),
      unfriend: vi.fn(),
    };

    const { now, sleep } = fakeClock();
    const result = await verifyByBio(client, "u1", "ABC123", { now, sleep });

    expect(result).toBe(true);
    expect(client.getUserById).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
  });

  it("keeps polling until the code appears, then stops", async () => {
    const client: VRChatBotClient = {
      getUserById: vi
        .fn()
        .mockResolvedValueOnce({ id: "u1", bio: "no code yet" })
        .mockResolvedValueOnce({ id: "u1", bio: "still nothing" })
        .mockResolvedValueOnce({ id: "u1", bio: "here it is XYZ789" }),
      sendFriendRequest: vi.fn(),
      getFriendStatus: vi.fn(),
      deleteFriendRequest: vi.fn(),
      unfriend: vi.fn(),
    };

    const { now, sleep } = fakeClock();
    const result = await verifyByBio(client, "u1", "XYZ789", { now, sleep, pollIntervalMs: 30_000 });

    expect(result).toBe(true);
    expect(client.getUserById).toHaveBeenCalledTimes(3);
    expect(sleep).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalledWith(30_000);
  });

  it("gives up and returns false once the timeout elapses", async () => {
    const client: VRChatBotClient = {
      getUserById: vi.fn().mockResolvedValue({ id: "u1", bio: "never has the code" }),
      sendFriendRequest: vi.fn(),
      getFriendStatus: vi.fn(),
      deleteFriendRequest: vi.fn(),
      unfriend: vi.fn(),
    };

    const { now, sleep } = fakeClock();
    const result = await verifyByBio(client, "u1", "NEVER1", {
      now,
      sleep,
      pollIntervalMs: 30_000,
      timeoutMs: 5 * 60_000,
    });

    expect(result).toBe(false);
    // 5 minutes / 30s = 10 polls before the deadline is reached.
    expect(client.getUserById).toHaveBeenCalledTimes(10);
  });
});

describe("verifyByFriendRequest", () => {
  it("sends a friend request, detects acceptance, and unfriends on success", async () => {
    const client: VRChatBotClient = {
      getUserById: vi.fn(),
      sendFriendRequest: vi.fn(),
      getFriendStatus: vi
        .fn()
        .mockResolvedValueOnce({ isFriend: false, outgoingRequest: true })
        .mockResolvedValueOnce({ isFriend: true, outgoingRequest: false }),
      deleteFriendRequest: vi.fn(),
      unfriend: vi.fn(),
    };

    const { now, sleep } = fakeClock();
    const result = await verifyByFriendRequest(client, "u2", { now, sleep, pollIntervalMs: 30_000 });

    expect(result).toBe(true);
    expect(client.sendFriendRequest).toHaveBeenCalledWith("u2");
    expect(client.unfriend).toHaveBeenCalledWith("u2");
    expect(client.deleteFriendRequest).not.toHaveBeenCalled();
  });

  it("cancels the stale outgoing request on timeout instead of leaving it pending forever", async () => {
    const client: VRChatBotClient = {
      getUserById: vi.fn(),
      sendFriendRequest: vi.fn(),
      getFriendStatus: vi.fn().mockResolvedValue({ isFriend: false, outgoingRequest: true }),
      deleteFriendRequest: vi.fn(),
      unfriend: vi.fn(),
    };

    const { now, sleep } = fakeClock();
    const result = await verifyByFriendRequest(client, "u3", {
      now,
      sleep,
      pollIntervalMs: 30_000,
      timeoutMs: 5 * 60_000,
    });

    expect(result).toBe(false);
    expect(client.deleteFriendRequest).toHaveBeenCalledWith("u3");
    expect(client.unfriend).not.toHaveBeenCalled();
  });
});
