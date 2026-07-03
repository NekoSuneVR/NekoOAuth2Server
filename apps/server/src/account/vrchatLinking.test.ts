import bcrypt from "bcryptjs";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { app } from "../app.js";
import { setVRChatBotClientForTesting } from "../connectors/vrchat/clientProvider.js";
import type { VRChatBotClient } from "../connectors/vrchat/types.js";
import { prisma } from "../db.js";

const TEST_PASSWORD = "correct-horse-battery-staple";
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function loginAgent(email: string) {
  await prisma.user.upsert({
    where: { primaryEmail: email },
    update: {},
    create: { primaryEmail: email, emailVerified: true, passwordHash: await bcrypt.hash(TEST_PASSWORD, 10) },
  });
  const agent = request.agent(app);
  await agent.post("/account/login").type("form").send({ email, password: TEST_PASSWORD });
  return agent;
}

afterAll(() => {
  setVRChatBotClientForTesting(null);
});

describe("VRChat linking: not configured", () => {
  it("responds 503 when no VRChat bot client is available", async () => {
    setVRChatBotClientForTesting(null);
    const agent = await loginAgent("vrchat-unconfigured-test@example.com");
    const res = await agent.post("/account/link/vrchat/bio").type("form").send({ vrchatUserId: "someone" });
    expect(res.status).toBe(503);
  });
});

describe("VRChat linking: bio mode, driven through the real route (not a shortcut)", () => {
  it("links once the generated code shows up in the polled bio", async () => {
    let currentBio = "";
    const fakeClient: VRChatBotClient = {
      getUserById: async (id) => ({ id, bio: currentBio }),
      sendFriendRequest: async () => {},
      getFriendStatus: async () => ({ isFriend: false, outgoingRequest: false }),
      deleteFriendRequest: async () => {},
      unfriend: async () => {},
    };
    setVRChatBotClientForTesting(fakeClient);

    const agent = await loginAgent("vrchat-bio-test@example.com");
    const vrchatUserId = "vrchat-bio-test-user";

    const res = await agent.post("/account/link/vrchat/bio").type("form").send({ vrchatUserId });
    expect(res.status).toBe(200);
    const match = res.text.match(/<strong>([A-Z0-9]{6})<\/strong>/);
    expect(match).toBeTruthy();

    // Only now does the bio "contain" the code — proves the route is really
    // polling in the background, not just creating the link immediately.
    currentBio = `check it out: ${match![1]}`;

    let linked = null;
    for (let i = 0; i < 20 && !linked; i += 1) {
      await sleep(100);
      linked = await prisma.linkedIdentity.findUnique({
        where: { provider_providerUserId: { provider: "vrchat", providerUserId: vrchatUserId } },
      });
    }

    expect(linked).toBeTruthy();
    expect(linked!.verifiedVia).toBe("bio");

    const user = await prisma.user.findUnique({ where: { primaryEmail: "vrchat-bio-test@example.com" } });
    expect(linked!.userId).toBe(user!.id);
  });
});

describe("VRChat linking: friend-request mode, driven through the real route", () => {
  it("links once the bot detects the friend request was accepted, and unfriends afterward", async () => {
    let isFriend = false;
    let unfriended = false;
    const fakeClient: VRChatBotClient = {
      getUserById: async (id) => ({ id, bio: "" }),
      sendFriendRequest: async () => {},
      getFriendStatus: async () => ({ isFriend, outgoingRequest: !isFriend }),
      deleteFriendRequest: async () => {},
      unfriend: async () => {
        unfriended = true;
      },
    };
    setVRChatBotClientForTesting(fakeClient);

    const agent = await loginAgent("vrchat-friend-test@example.com");
    const vrchatUserId = "vrchat-friend-test-user";

    const res = await agent.post("/account/link/vrchat/friend").type("form").send({ vrchatUserId });
    expect(res.status).toBe(200);

    isFriend = true;

    let linked = null;
    for (let i = 0; i < 20 && !linked; i += 1) {
      await sleep(100);
      linked = await prisma.linkedIdentity.findUnique({
        where: { provider_providerUserId: { provider: "vrchat", providerUserId: vrchatUserId } },
      });
    }

    expect(linked).toBeTruthy();
    expect(linked!.verifiedVia).toBe("friend_request");
    expect(unfriended).toBe(true);
  });
});
