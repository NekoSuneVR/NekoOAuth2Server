import express from "express";
import { config } from "./config.js";

const app = express();

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.listen(config.port, () => {
  console.log(`NekoOAuth2Server listening on port ${config.port}`);
});
