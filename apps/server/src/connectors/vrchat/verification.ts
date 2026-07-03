import crypto from "node:crypto";
import type { VRChatBotClient } from "./types.js";

const CODE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// Matches SocialLinkUpOnly's proven bio-verification code shape exactly
// (see TODO.md Phase 4) — 6-character alphanumeric.
export function generateVerificationCode(): string {
  let code = "";
  for (let i = 0; i < 6; i += 1) {
    code += CODE_CHARS[crypto.randomInt(CODE_CHARS.length)];
  }
  return code;
}

export interface PollOptions {
  pollIntervalMs?: number;
  timeoutMs?: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}

// Overridable via env so integration tests can drive the *real* route code
// (account/router.ts calls these with no explicit opts) without waiting real
// minutes — production behavior is unaffected since these vars are unset.
// Read lazily (at call time, not module-load time): this module can be
// reached before config.ts's `import "dotenv/config"` has actually run,
// depending on which entry point imports what first, so a top-level
// `const ... = process.env.X` would silently lock in "unset" — found by the
// account-linking test itself timing out with the override seemingly ignored.
function defaultPollIntervalMs(): number {
  return Number(process.env.VRCHAT_VERIFY_POLL_INTERVAL_MS) || 30_000;
}
function defaultTimeoutMs(): number {
  return Number(process.env.VRCHAT_VERIFY_TIMEOUT_MS) || 5 * 60_000;
}
const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Bio-code mode: the user pastes a generated code into their VRChat bio; this
 * polls their public profile until it shows up or the timeout elapses.
 * Mirrors SocialLinkUpOnly's `auth/vrchat.js` bio-mode exactly (30s poll
 * interval, 5-minute timeout) rather than inventing new numbers.
 */
export async function verifyByBio(
  client: VRChatBotClient,
  vrchatUserId: string,
  code: string,
  opts: PollOptions = {},
): Promise<boolean> {
  const pollIntervalMs = opts.pollIntervalMs ?? defaultPollIntervalMs();
  const timeoutMs = opts.timeoutMs ?? defaultTimeoutMs();
  const sleep = opts.sleep ?? defaultSleep;
  const now = opts.now ?? Date.now;

  const deadline = now() + timeoutMs;
  do {
    const user = await client.getUserById(vrchatUserId);
    if (user.bio.includes(code)) return true;
    if (now() >= deadline) return false;
    await sleep(pollIntervalMs);
  } while (now() < deadline);
  return false;
}

/**
 * Friend-request mode: the bot sends the user a friend request; this polls
 * until they accept or the timeout elapses, then cleans up either way — auto
 * -unfriends on success, cancels the stale outgoing request on timeout.
 * Mirrors SocialLinkUpOnly's `auth/vrchat.js` friend-mode exactly.
 */
export async function verifyByFriendRequest(
  client: VRChatBotClient,
  vrchatUserId: string,
  opts: PollOptions = {},
): Promise<boolean> {
  const pollIntervalMs = opts.pollIntervalMs ?? defaultPollIntervalMs();
  const timeoutMs = opts.timeoutMs ?? defaultTimeoutMs();
  const sleep = opts.sleep ?? defaultSleep;
  const now = opts.now ?? Date.now;

  await client.sendFriendRequest(vrchatUserId);

  const deadline = now() + timeoutMs;
  let verified = false;
  do {
    const status = await client.getFriendStatus(vrchatUserId);
    if (status.isFriend) {
      verified = true;
      break;
    }
    if (now() >= deadline) break;
    await sleep(pollIntervalMs);
  } while (now() < deadline);

  if (verified) {
    await client.unfriend(vrchatUserId);
  } else {
    await client.deleteFriendRequest(vrchatUserId);
  }
  return verified;
}
