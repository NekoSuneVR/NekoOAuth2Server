import cookieParser from "cookie-parser";
import express from "express";
import { accountRouter } from "./account/router.js";
import { profileApiRouter } from "./account/profileApi.js";
import { auditLogApiRouter } from "./admin/auditLogApi.js";
import { clientsApiRouter } from "./admin/clientsApi.js";
import { connectorsApiRouter } from "./admin/connectorsApi.js";
import { rolesApiRouter } from "./admin/rolesApi.js";
import { usersApiRouter } from "./admin/usersApi.js";
import { webhooksApiRouter } from "./admin/webhooksApi.js";
import { authorizeRateLimiter, tokenRateLimiter } from "./security/rateLimit.js";
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

// Client management (Phase 8) — the first admin API `apps/console` actually
// calls for real, not just a documented gap.
app.use("/api/admin/clients", express.json(), clientsApiRouter);

// Audit log (Phase 9) — read-only, see src/audit/log.ts for what's recorded.
app.use("/api/admin/audit-log", auditLogApiRouter);

// Webhook management (Phase 8/9) — register/rotate/resend, see src/webhooks/deliver.ts for the hardening.
app.use("/api/admin/webhooks", express.json(), webhooksApiRouter);

// Connector management (Phase 8/9) — DB-backed config, see src/connectors/registry.ts.
app.use("/api/admin/connectors", express.json(), connectorsApiRouter);

// User/role/session management (Phase 8/9) — view users, grant/revoke roles,
// force-revoke sessions, admin-triggered deletion.
app.use("/api/admin/users", express.json(), usersApiRouter);
app.use("/api/admin/roles", express.json(), rolesApiRouter);

// Rate limiting (Phase 9) — registered as path-scoped `use()` middleware
// ahead of oidc-provider's own catch-all callback below, since Express only
// applies path-scoped middleware to matching requests before falling
// through, it can't be bolted onto oidc-provider's internal Koa router
// after the fact.
app.use("/oidc/auth", authorizeRateLimiter);
app.use("/oidc/token", tokenRateLimiter);

// Both mounted under /oidc: oidc-provider derives its own mount path from the
// issuer URL's pathname (here, "/oidc") and computes the interaction redirect
// (its default interactions.url) relative to that — `/oidc/interaction/:uid`,
// not root-relative — confirmed by watching the real redirect Location header
// rather than assuming it. Registered first so Express tries these routes
// before falling through to oidc-provider's own callback.
app.use("/oidc", interactionsRouter);
app.use("/oidc", oidcProvider.callback());
