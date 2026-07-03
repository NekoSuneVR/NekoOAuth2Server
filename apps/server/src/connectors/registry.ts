import { createDiscordConnector } from "./providers/discord.js";
import { createRobloxConnector } from "./providers/roblox.js";
import { createTwitchConnector } from "./providers/twitch.js";
import { createVpzoneConnector } from "./providers/vpzone.js";
import type { UpstreamConnector } from "./types.js";

const PROVIDERS: Array<{ id: string; create: (clientId: string, clientSecret: string) => UpstreamConnector }> = [
  { id: "discord", create: createDiscordConnector },
  { id: "roblox", create: createRobloxConnector },
  { id: "twitch", create: createTwitchConnector },
  { id: "vpzone", create: createVpzoneConnector },
];

// A provider is only registered (and only then shown as a "Sign in with X"
// option) if its credentials are actually configured — booting the server
// without, say, DISCORD_CLIENT_ID set just means Discord login isn't offered
// yet, not a crash.
function buildRegistry(): Map<string, UpstreamConnector> {
  const registry = new Map<string, UpstreamConnector>();
  for (const provider of PROVIDERS) {
    const clientId = process.env[`${provider.id.toUpperCase()}_CLIENT_ID`];
    const clientSecret = process.env[`${provider.id.toUpperCase()}_CLIENT_SECRET`];
    if (clientId && clientSecret) {
      registry.set(provider.id, provider.create(clientId, clientSecret));
    }
  }
  return registry;
}

export const connectorRegistry = buildRegistry();

/** Test-only escape hatch for registering a mock connector without real env vars. */
export function registerConnector(id: string, connector: UpstreamConnector) {
  connectorRegistry.set(id, connector);
}
