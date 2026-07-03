import express from "express";
import { config } from "./config.js";
import { oidcProvider } from "./oidc/provider.js";

const app = express();

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use("/oidc", oidcProvider.callback());

app.listen(config.port, () => {
  console.log(`NekoOAuth2Server listening on port ${config.port}`);
});
