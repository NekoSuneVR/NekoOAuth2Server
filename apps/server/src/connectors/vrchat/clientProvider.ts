import type { VRChatBotClient } from "./types.js";
import { createVRChatBotClientFromEnv } from "./realClient.js";

// Same "test-only escape hatch" pattern as connectors/registry.ts's
// registerConnector — there's no real VRChat bot account in this
// environment, so tests inject a fake client here instead of going through
// real env-var credentials.
let override: VRChatBotClient | null | undefined;

export async function getVRChatBotClient(): Promise<VRChatBotClient | null> {
  if (override !== undefined) return override;
  return createVRChatBotClientFromEnv();
}

export function setVRChatBotClientForTesting(client: VRChatBotClient | null): void {
  override = client;
}
