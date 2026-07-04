import { app } from "./app.js";
import { config } from "./config.js";
import { loadConnectorRegistryFromDb, migrateEnvConnectorsIfEmpty } from "./connectors/registry.js";

async function start() {
  // One-time env-var-to-database migration (no-op once any Connector row
  // exists), then populate the live registry from the database — see
  // src/connectors/registry.ts.
  await migrateEnvConnectorsIfEmpty();
  await loadConnectorRegistryFromDb();

  app.listen(config.port, () => {
    console.log(`NekoOAuth2Server listening on port ${config.port}`);
  });
}

start().catch((err) => {
  console.error("Failed to start NekoOAuth2Server:", err);
  process.exit(1);
});
