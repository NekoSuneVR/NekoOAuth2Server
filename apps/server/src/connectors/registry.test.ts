import { beforeEach, describe, expect, it } from "vitest";
import { prisma } from "../db.js";
import { decryptSecret, isEncryptedSecret } from "../security/encryption.js";
import { loadConnectorRegistryFromDb, migrateEnvConnectorsIfEmpty, connectorRegistry } from "./registry.js";

const ENV_KEYS = ["DISCORD_CLIENT_ID", "DISCORD_CLIENT_SECRET", "ROBLOX_CLIENT_ID", "ROBLOX_CLIENT_SECRET"];

describe("migrateEnvConnectorsIfEmpty", () => {
  beforeEach(async () => {
    // Isolated per test: only ever touches rows this suite itself created.
    await prisma.connector.deleteMany({
      where: { providerId: { in: ["discord", "roblox", "twitch", "vpzone"] } },
    });
    for (const key of ENV_KEYS) delete process.env[key];
    connectorRegistry.clear();
  });

  it("creates Connector rows from legacy env vars when the table is empty", async () => {
    process.env.DISCORD_CLIENT_ID = "legacy-discord-id";
    process.env.DISCORD_CLIENT_SECRET = "legacy-discord-secret";
    process.env.ROBLOX_CLIENT_ID = "legacy-roblox-id";
    process.env.ROBLOX_CLIENT_SECRET = "legacy-roblox-secret";

    await migrateEnvConnectorsIfEmpty();

    const discordRow = await prisma.connector.findUnique({ where: { providerId: "discord" } });
    expect(discordRow).toBeTruthy();
    expect(discordRow!.clientId).toBe("legacy-discord-id");
    expect(isEncryptedSecret(discordRow!.clientSecret)).toBe(true);
    expect(decryptSecret(discordRow!.clientSecret)).toBe("legacy-discord-secret");
    expect(discordRow!.presetId).toBe("discord");
    expect(discordRow!.enabled).toBe(true);

    const robloxRow = await prisma.connector.findUnique({ where: { providerId: "roblox" } });
    expect(robloxRow).toBeTruthy();

    // Twitch/VPZone env vars were never set — no row for them.
    const twitchRow = await prisma.connector.findUnique({ where: { providerId: "twitch" } });
    expect(twitchRow).toBeNull();

    await loadConnectorRegistryFromDb();
    expect(connectorRegistry.has("discord")).toBe(true);
    expect(connectorRegistry.has("roblox")).toBe(true);
  });

  it("does nothing if any Connector row already exists (not a repeated migration)", async () => {
    await prisma.connector.create({
      data: {
        providerId: "some-other-connector",
        displayName: "Some Other Connector",
        type: "oauth2",
        clientId: "x",
        clientSecret: "y",
        scope: "openid",
        pkce: "required",
      },
    });

    process.env.DISCORD_CLIENT_ID = "legacy-discord-id";
    process.env.DISCORD_CLIENT_SECRET = "legacy-discord-secret";

    await migrateEnvConnectorsIfEmpty();

    const discordRow = await prisma.connector.findUnique({ where: { providerId: "discord" } });
    expect(discordRow).toBeNull();

    await prisma.connector.deleteMany({ where: { providerId: "some-other-connector" } });
  });

  it("does nothing when no legacy env vars are set at all", async () => {
    await migrateEnvConnectorsIfEmpty();
    const count = await prisma.connector.count();
    expect(count).toBe(0);
  });
});
