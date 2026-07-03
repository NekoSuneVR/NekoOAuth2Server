import { VRChat } from "vrchat";
import type { VRChatBotClient } from "./types.js";

export interface VRChatBotCredentials {
  username: string;
  password: string;
  /** TOTP secret — the client generates and submits the 2FA code itself, no manual verify2Fa step needed. */
  totpSecret: string;
}

/**
 * Real bot client backed by the actual `vrchat` npm package (verified
 * against its real, installed v2.21.7 API surface — `VRChat` class,
 * `login({ username, password, totpSecret })` handling 2FA internally,
 * `getUser`/`friend`/`getFriendStatus`/`deleteFriendRequest`/`unfriend`
 * methods, all `{ path: { userId } }`-shaped). NOT live-tested — there's no
 * real VRChat bot account available in this environment. The pure
 * verification logic that doesn't need a live account (verification.test.ts)
 * is real-tested; this thin adapter layer is the untested part.
 */
export async function createRealVRChatBotClient(credentials: VRChatBotCredentials): Promise<VRChatBotClient> {
  const client = new VRChat({
    application: {
      name: "NekoOAuth2Server",
      version: "0.1.0",
      contact: "https://github.com/nekosunevr",
    },
  });

  await client.login({
    username: credentials.username,
    password: credentials.password,
    totpSecret: credentials.totpSecret,
    throwOnError: true,
  });

  return {
    async getUserById(userId) {
      const { data } = await client.getUser({ path: { userId }, throwOnError: true });
      return { id: data.id, bio: data.bio };
    },
    async sendFriendRequest(userId) {
      await client.friend({ path: { userId }, throwOnError: true });
    },
    async getFriendStatus(userId) {
      const { data } = await client.getFriendStatus({ path: { userId }, throwOnError: true });
      return { isFriend: data.isFriend, outgoingRequest: data.outgoingRequest };
    },
    async deleteFriendRequest(userId) {
      await client.deleteFriendRequest({ path: { userId }, throwOnError: true });
    },
    async unfriend(userId) {
      await client.unfriend({ path: { userId }, throwOnError: true });
    },
  };
}

/**
 * Only attempts a real bot login if credentials are actually configured —
 * same "feature disabled, not a crash" pattern as the OAuth2 connector
 * registry. Returns null when unconfigured.
 */
export async function createVRChatBotClientFromEnv(): Promise<VRChatBotClient | null> {
  const username = process.env.VRCHAT_BOT_USERNAME;
  const password = process.env.VRCHAT_BOT_PASSWORD;
  const totpSecret = process.env.VRCHAT_BOT_TOTP_SECRET;

  if (!username || !password || !totpSecret) return null;
  return createRealVRChatBotClient({ username, password, totpSecret });
}
