import cookieParser from "cookie-parser";
import express from "express";
import { accountRouter } from "./account/router.js";
import { profileApiRouter } from "./account/profileApi.js";
import { emailTemplatesRouter } from "./email/templatesApi.js";
import { smtpConfigRouter } from "./email/smtpConfigApi.js";
import { interactionsRouter } from "./oidc/interactions.js";
import { oidcProvider } from "./oidc/provider.js";
import { requirePermission } from "./rbac/requirePermission.js";

export const app = express();

app.use(cookieParser());

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// Self-service account portal (Phase 5) — view/link/unlink identities,
// delete your own account. Uses its own signed cookie session (account/
// session.ts), separate from oidc-provider's internal interaction session.
app.use("/account", accountRouter);

// Write-side counterpart to reading profile fields via /oidc/me — a
// downstream app can update whatever it's been granted scope for.
app.use("/api/profile", express.json(), profileApiRouter);

// Example protected endpoint demonstrating RBAC enforcement (Phase 3) — the
// pattern any real admin API (Phase 8) would follow, since that API doesn't
// exist yet to enforce this on for real.
app.get("/api/internal/admin-ping", requirePermission("admin:access"), (_req, res) => {
  res.json({ ok: true });
});

// Transactional email admin API (Phase 6) — the backend half of a future
// admin console screen (Phase 8 hasn't started yet, same gap as above).
app.use("/api/admin/email-templates", express.json(), emailTemplatesRouter);
app.use("/api/admin/smtp-config", express.json(), smtpConfigRouter);

// Both mounted under /oidc: oidc-provider derives its own mount path from the
// issuer URL's pathname (here, "/oidc") and computes the interaction redirect
// (its default interactions.url) relative to that — `/oidc/interaction/:uid`,
// not root-relative — confirmed by watching the real redirect Location header
// rather than assuming it. Registered first so Express tries these routes
// before falling through to oidc-provider's own callback.
app.use("/oidc", interactionsRouter);
app.use("/oidc", oidcProvider.callback());
