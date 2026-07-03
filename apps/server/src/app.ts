import express from "express";
import { interactionsRouter } from "./oidc/interactions.js";
import { oidcProvider } from "./oidc/provider.js";
import { requirePermission } from "./rbac/requirePermission.js";

export const app = express();

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// Example protected endpoint demonstrating RBAC enforcement (Phase 3) — the
// pattern any real admin API (Phase 8) would follow, since that API doesn't
// exist yet to enforce this on for real.
app.get("/api/internal/admin-ping", requirePermission("admin:access"), (_req, res) => {
  res.json({ ok: true });
});

// Both mounted under /oidc: oidc-provider derives its own mount path from the
// issuer URL's pathname (here, "/oidc") and computes the interaction redirect
// (its default interactions.url) relative to that — `/oidc/interaction/:uid`,
// not root-relative — confirmed by watching the real redirect Location header
// rather than assuming it. Registered first so Express tries these routes
// before falling through to oidc-provider's own callback.
app.use("/oidc", interactionsRouter);
app.use("/oidc", oidcProvider.callback());
