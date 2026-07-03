# NekoOAuth2Server — Roadmap / TODO

This is the working plan for building NekoOAuth2Server: a self-hosted OIDC/OAuth 2.1 identity provider — Logto-inspired, but self-built — meant to be the *one* login server every Neko\* project federates through, instead of each project running its own separate Discord OAuth app and disconnected user table.

Legend: `[ ]` not started · `[~]` in progress · `[x]` done

---

## Phase 0 — Planning & Decisions

- [x] Write initial README.md, TODO.md
- [x] Decide project license → **AGPL-3.0**. This server holds auth secrets and user data for every other Neko\* project; the network-use clause means anyone who forks this and runs a modified version as a hosted service has to release their changes too — closes the "quietly resell my work" loophole plain GPL leaves open for server software.
- [x] Decide core language/runtime → **Node.js + TypeScript**, confirmed after auditing every other Neko\* web project. Node/TS is used in 14 of 15 surveyed projects; it's the only realistic choice for staying consistent with the rest of the ecosystem this server has to interoperate with.
- [x] Decide database → **PostgreSQL** (not the more common MySQL/MariaDB seen across older Neko\* projects) — better fit for the JSON columns, row-level constraints, and relational RBAC/multi-tenancy data this project actually needs, and it's what Logto itself uses.
- [x] Decide repo layout → **pnpm monorepo**: `apps/server` (OIDC core), `apps/console` (admin dashboard, added when Phase 8 starts), `packages/shared` (types/schemas), `packages/sdk` (client library for downstream Neko\* apps to consume) — same shape as `account-recovery-keychain`.
- [x] Decide how to build the OIDC/OAuth core → **do not hand-roll authorization-code/PKCE/JWT crypto from scratch.** Build on a mature, widely-audited Node OIDC provider library (leading candidate: `panva/oidc-provider`, which is also what Logto's own `core` package is built on) and put the "own version" effort into the data model, multi-tenancy, RBAC, admin console, and downstream SDK instead. A bug in hand-rolled token-signing code would compromise every federated Neko\* site at once.
- [x] Researched Logto's actual architecture (`logto-io/logto` on GitHub) for a rough reference map — see notes below. Confirms the plan rather than changing it.
- [x] Decide the connector architecture → **generic, config-driven connector types, not bespoke code per provider.** Logto's own `connectors` packages confirm this pattern: a standard connector interface (`getAuthorizationUri`, `authorizationCallbackHandler`, `getAccessToken`, `getUserInfo`) is implemented once each for a **generic OAuth 2.0 connector** and a **generic OIDC connector**; individual providers (Google, Discord, etc.) are then just pre-filled *config profiles* (authorize/token/userinfo URLs, client id/secret, scopes) of one of those two generic types. Only providers with genuinely non-standard flows (SAML, or — in our case, VRChat, which has no OAuth2 at all) need real custom code. This is the same "reuse a proven shape, don't hand-roll 40 times" reasoning as the OIDC-library decision above.
- [x] Decide ORM → **Prisma** (matches `account-recovery-keychain`, our newest/most security-conscious project). Note for reference, not a reason to switch: Logto's own core uses Slonik (a query builder) + Zod schemas instead of a traditional ORM — a valid alternative approach, but Prisma keeps us consistent with our own house pattern.
- [x] Decide account-deletion / data-lifecycle model → a **signed webhook system** (HMAC-signed payloads, delivery log, matching Logto's Console → Webhooks model) so that when a user deletes their account here, every downstream Neko\* app subscribed via the SDK gets a `user.deleted` event and purges its own locally cached copy of that user's data. Deleting an account on this server must actually remove the person's data everywhere it's been shared, not just here.
- [x] Confirm the OIDC provider library → **`panva/oidc-provider`**, confirmed rather than assumed. As of this check: v9.8.6 (actively released, 2,848 commits), MIT licensed, ~3.8k GitHub stars, and genuinely **OpenID Certified** (Basic, Implicit, Hybrid, FAPI 1.0, FAPI CIBA, FAPI 2.0 profiles) — not just popular, independently certified spec-conformant. It implements RFC 7636 PKCE natively and documents a clear custom-`Adapter` interface (`upsert`/`find`/`findByUserCode`/`findByUid`/`consume`/`destroy`/`revokeByGrantId`/`findByPayloadValueSet`), which is exactly the seam Phase 1 needs to back it with our own Prisma/Postgres storage instead of its default in-memory adapter. Also confirmed to be what Logto's own `core` package is built on — same library, independently arrived at.
- [x] Decide the shape of the "shared identity" data model:
  - **`User`** (this server's own identity) — `id`, `primaryEmail` (nullable + `emailVerified`), `displayName`, `avatarUrl`, `status` (`active`/`suspended`/`deleted`), timestamps. This is the *only* place a person's core identity lives — deliberately thin.
  - **`LinkedIdentity`** — one row per external platform link: `userId` FK, `provider` (`discord`/`vrchat`/`roblox`/`twitch`/`vpzone`/…), `providerUserId`, `providerUsername`, `verifiedVia` (`oauth` for standard connectors, `bio` or `friend_request` for VRChat's bot-verified flow — see Phase 4), `linkedAt`. Unique on `(provider, providerUserId)` so one external account can't be linked to two different NekoOAuth2Server users. This is Phase 5's multi-connector linking, generalized from `SocialLinkUpOnly`'s single-project `LinkedAccount` table.
  - **`ClientConsent`** — `userId` + `clientId` FKs, `grantedScopes` (string array), `grantedAt`, `revokedAt` (nullable). This is *the* answer to "what can a downstream app read": a client only ever receives the `User` fields and `LinkedIdentity` rows covered by scopes it was actually granted — e.g. `profile`, `email`, and per-platform scopes like `identity:discord` / `identity:vrchat` — nothing else, and it doubles as the self-service "apps with access to your data" screen (Phase 5/8).
  - **Explicitly not stored here**: any per-project data (a game inventory, a site-specific subscription tier, etc.). That stays in each downstream Neko\* app's own database, keyed by the `sub` claim this server issues. This server is identity + linked platforms + consent, nothing more — keeps the single point of failure as small as it can be.

### Reference notes from studying Logto's architecture (not our code, just what informed the decisions above)

- Monorepo shape: `core` (OIDC server), `console` (admin SPA), `experience` (end-user sign-in/sign-up UI, kept separate from the admin console), `schemas` (DB row shapes via Zod), `connectors` (one package per provider/protocol), `toolkit` (shared libs incl. `connector-kit`, the interface connectors implement), `cli` (migrations/seeding).
- Multi-tenancy: **organization-level** multi-tenancy (tenants-within-a-product, RBAC per organization) is in Logto's open-source core. *Console-level* multi-tenancy (managing several separate Logto instances from one admin login) is Cloud-only — not relevant to us since we're self-hosting one instance for ourselves.
- RBAC: global app-level roles/permissions plus an "organization template" — one shared role/permission set applied consistently per-organization, with a user able to hold different roles in different organizations. Reasonable shape to borrow for Phase 3.
- Email: pluggable "email connectors" (built-in/SendGrid/Mailgun/SMTP/generic HTTP), each implementing a common send interface; templates keyed by `usageType` (`Register`, `SignIn`, `ForgotPassword`, `Generic`, etc.) with a `{{code}}` placeholder. This is exactly the model Phase 6 below follows, scoped to SMTP only for v1.

## Phase 1 — Core Server Skeleton

- [x] Scaffold `apps/server` — minimal Express + TypeScript app with a `/health` endpoint, env-based config, and a build/dev script. No OIDC logic yet — just proves the workspace boots. **Verified live**: `pnpm install` succeeds, `pnpm --filter server dev` boots, and `curl localhost:4000/health` returns `{"status":"ok"}`.
- [ ] `docker-compose.yml` for **local dev only** (Postgres container + adminer/pgweb) so development doesn't depend on a hand-installed Postgres — separate from the full production Docker setup in Phase 10
- [ ] Set up Prisma + PostgreSQL connection, initial migration (empty/placeholder schema)
- [ ] Wire the chosen OIDC provider library into `apps/server`, backed by a custom Postgres storage adapter (not the library's default in-memory/redis adapter)
- [ ] Define initial Prisma schema per Phase 0's data model decision: `Tenant`, `Client` (per-project OAuth app registration), `User`, `Session`, `LinkedIdentity`, `ClientConsent`
- [ ] Confirm PKCE is enforced for every client type (including confidential clients) at the library-config level, not just public clients — write a test that a code exchange without a valid `code_verifier` is rejected

## Phase 2 — OAuth 2.1 / OIDC Compliance

- [ ] Authorization code flow, end to end, against a real test client
- [ ] Refresh token rotation (reuse detection: a replayed old refresh token revokes the whole token family)
- [ ] Client credentials flow for service-to-service calls between Neko\* backends
- [ ] JWKS endpoint + key rotation strategy
- [ ] Discovery document (`/.well-known/openid-configuration`)
- [ ] Scope/claims model: define the standard scopes downstream Neko\* apps request (`profile`, `email`, per-project custom scopes)

## Phase 3 — Multi-Tenancy & RBAC

- [ ] Tenant isolation model (decide: fully isolated orgs, or a single "Neko" tenant with per-client scoping — revisit Phase 0's open question once real usage patterns are clearer)
- [ ] Role/permission schema, scoped per client application (and, if useful, per-organization along Logto's "organization template" shape — one shared role/permission set, different assignments per org)
- [ ] Enforce RBAC checks in issued token claims and on the admin API
- [ ] Tests: a user with role X in Project A cannot use that role's permissions when authenticating to Project B

## Phase 4 — SSO / Upstream Connectors

**Architecture**: two generic, config-driven connector types (see Phase 0 decision) implementing one shared interface — `getAuthorizationUri`, `authorizationCallbackHandler`, `getAccessToken`, `getUserInfo` — plus one genuinely custom connector type for platforms with no OAuth2 at all.

- [ ] Build the **generic OAuth 2.0 connector** type: config = authorization URL, token URL, userinfo URL, `client_id`/`client_secret`, scopes, PKCE method
- [ ] Build the **generic OIDC connector** type on top of the same interface: adds discovery-document support and ID token validation
- [ ] Document the connector plugin interface so more providers (or bot-verified connectors, see below) can be added later without touching core

### Standard connectors (config profiles of the generic OAuth 2.0/OIDC connector)

Confirmed via auditing our own `SocialLinkUpOnly` project's real implementations — these three already work as real OAuth2 there, so this is porting proven flows, not guessing:

- [ ] **Discord** — highest priority; every existing Neko\* site already depends on it
- [ ] **Roblox** — real OAuth2 + PKCE (S256) against `apis.roblox.com/oauth/v1/{authorize,token}` and `/userinfo`, confirmed working in `SocialLinkUpOnly`
- [ ] **Twitch** — real OAuth2 against `id.twitch.tv/oauth2/{authorize,token}` + `api.twitch.tv/helix/users`, confirmed working in `SocialLinkUpOnly`
- [ ] **VPZone** — real OAuth2 + mandatory PKCE (S256). Confirmed flow: register an app for a `client_id`/`client_secret` → redirect to `https://vpzone.tv/oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=...&state=...&code_challenge=...&code_challenge_method=S256` → user approves → redirected back with `?code=...&state=...` → exchange at `POST https://vpzone.tv/api/oauth/token` → call `https://vpzone.tv/api/v1/*` with `Authorization: Bearer vpz_at_...`

Broader standard-connector backlog, in roughly the order they're likely to matter for Neko\* projects (endpoint details to confirm per-provider against [Logto's OAuth Providers Explorer](https://logto.io/oauth-providers-explorer) and each provider's own docs before marking done):

- [ ] Google
- [ ] GitHub
- [ ] Microsoft
- [ ] Facebook
- [ ] Apple
- [ ] Steam
- [ ] Spotify
- [ ] GitLab
- [ ] LinkedIn
- [ ] Slack
- [ ] Patreon
- [ ] Amazon
- [ ] X (Twitter)

### Bot-verified connectors (no usable OAuth2 exists)

- [ ] **VRChat** — VRChat has no public OAuth2 at all, so this cannot be a generic-connector preset. Port the proven design from `SocialLinkUpOnly` (`auth/vrchat.js`) exactly rather than reinventing it:
  - **Bio mode**: generate a 6-character alphanumeric code, ask the user to paste it into their VRChat bio, poll the user's profile every 30s (5-minute timeout) checking `bio.includes(code)`
  - **Friend-request mode**: have a bot account send the user a VRChat friend request, poll friend status every 30s (5-minute timeout), then auto-unfriend once verified
  - Both modes need a bot account with real VRChat credentials + TOTP, driven through the unofficial `vrchat` npm client — **decide**: stand up our own bot microservice, or call the existing `VRCLogger/BACKEND` service internally the same way `SocialLinkUpOnly` does (its `VRC_EXTERNAL_API_BASE_URL`)? Reusing `VRCLogger/BACKEND` avoids running a second VRChat bot login, but couples this server's uptime to that project's.
  - Store only `platformUserId` + username on success, matching `SocialLinkUpOnly`'s `LinkedAccount` model — no VRChat credentials or tokens of the *user's* ever touch this server, only the bot's own.

## Phase 5 — Shared Identity, Account Linking & Data Lifecycle

- [ ] Define which profile fields are global (shared across every Neko\* project) vs. per-project-only
- [ ] Consent screen: a downstream app requesting a new scope shows the user exactly what data it's asking for
- [ ] **Multi-connector linking**: a user can link more than one external identity to a single NekoOAuth2Server account (e.g. Discord + VRChat + Twitch + Roblox all on one account) — list/link/unlink UI and API, mirroring `SocialLinkUpOnly`'s `LinkedAccount` model but centralized here instead of per-project
- [ ] API for a downstream app to read/update the shared profile fields it's been granted scope for
- [ ] **Self-service account deletion**: a user can delete their own account
- [ ] **Deletion cascade**: deleting an account fires a signed `user.deleted` webhook (see Phase 0's decision) to every downstream app that has ever authenticated that user, so each app can purge its own cached copy — deletion here has to mean deletion everywhere this identity has been shared, not just in this server's own database
- [ ] Migration plan: how existing per-project user tables (Discord ID, etc.) map onto the new shared identity when a site adopts this server

## Phase 6 — Transactional Email / SMTP System

- [ ] SMTP connector config (host/port/username/password/from-address), admin-configurable — v1 is SMTP-only; a pluggable interface (matching Logto's email-connector shape) can add SendGrid/Mailgun/HTTP-based providers later without a redesign
- [ ] Template system keyed by `usageType`, matching Logto's model exactly: `SignIn`, `Register`, `ForgotPassword`, `OrganizationInvitation`, `Generic`, `UserPermissionValidation`, `BindNewIdentifier`, `MfaVerification`, `BindMfa`
- [ ] Seed default templates from `apps/server/seed-data/email-templates.json` (already drafted — HTML, `{{code}}` placeholder per usage type). **Note**: these drafts use a purple accent (`#6d28d9`); reconcile with the green brand theme decided for the console (Phase 8) before these ship as the real defaults, either by re-skinning them or keeping transactional email on its own accent independent of the console's UI theme
- [ ] Admin console screen: edit subject + HTML per `usageType`, with a live preview and the `{{code}}` (and any other) placeholders clearly documented
- [ ] Rate limit and log every send (who, when, which template) — this sends real emails to real users, needs the same care as the audit log in Phase 9

## Phase 7 — Client SDK for Downstream Neko\* Apps

- [ ] `packages/sdk` — thin library wrapping: redirect-to-login, PKCE code_verifier generation/storage, token exchange, JWKS-based token verification, shared-profile fetch
- [ ] Framework-agnostic core + a small Express middleware helper (since Express is the dominant framework across existing Neko\* sites)
- [ ] Webhook receiver helper: verify the HMAC signature on incoming `user.deleted` (and other) webhook events and hand off to an app-supplied handler — every downstream app needs this to honor Phase 5's deletion cascade
- [ ] Migrate one real existing Neko\* project (candidate: a site currently using Passport + Discord OAuth directly) to use this SDK, end to end, as the first real integration test
- [ ] Document the "how to add login to a new Neko\* project in under 10 minutes" flow

## Phase 8 — Admin Console

- [ ] Scaffold `apps/console` — **Next.js** (matching `account-recovery-keychain`'s precedent), **Tailwind CSS**, dark theme, green accent scale (reuse `account-recovery-keychain`'s dark-surface + green `brand` token approach rather than inventing a new palette), aiming for a genuinely modern/polished feel — this is the one piece of the whole system every admin interaction goes through, worth the design effort
- [ ] Manage clients (register a new downstream project, rotate its secret)
- [ ] Manage users, roles, sessions (view + force-revoke), and each user's linked connectors (Phase 5)
- [ ] **Connector management screen**: a grid of provider cards (à la Logto's "Add Social Connector" picker) for one-click named presets, plus a "customize by standard protocol" path exposing the raw generic OAuth 2.0 / OIDC connector config for any provider not in the preset list
- [ ] Email/SMTP connector + template editor (Phase 6)
- [ ] Webhook management: register endpoints, view delivery logs/signing secret, resend failed deliveries
- [ ] Audit log viewer

## Phase 9 — Security Hardening & Audit Logging

- [ ] Structured audit log for every login, token issuance/revocation, and admin action
- [ ] Rate limiting on token/authorize endpoints
- [ ] Session/device management for end users (list active sessions, "log out everywhere")
- [ ] Secret handling review: client secrets, signing keys, upstream provider credentials, bot account credentials (Phase 4's VRChat bot) — never logged, encrypted at rest
- [ ] Webhook hardening: signing-secret rotation, delivery retries/backoff, no SSRF via user-supplied webhook URLs
- [ ] Security review pass before any real project migrates over (see `account-recovery-keychain`'s security-model write-up for the bar to hit)

## Phase 10 — Docker & Deployment

- [ ] `Dockerfile` for `apps/server` (multi-stage: build, slim runtime, non-root user)
- [ ] `Dockerfile` for `apps/console`
- [ ] `docker-compose.yml` — full stack: server + console + PostgreSQL, distinct from Phase 1's dev-only compose file
- [ ] Document required environment variables and config precedence (including SMTP and OIDC-library settings)
- [ ] Health checks + graceful shutdown
- [ ] Backup/restore plan for the Postgres database (this becomes the single source of truth for auth across every project — losing it is not a "restart the container" problem)

## Phase 11 — Docs & Public Release

- [ ] Finalize README (replace "early planning" status once Phase 1–2 are real)
- [ ] Per-project integration guide using the Phase 7 SDK
- [ ] CONTRIBUTING.md
- [ ] Tag v0.1.0, set up CI (build/lint/test)

---

## Open Questions

- Single shared tenant for all first-party Neko\* projects, or one tenant per project from day one? Affects Phase 3's isolation model.
- Should this server also issue API keys for pure machine-to-machine Neko\* integrations (e.g. bot-to-bot), or is that out of scope and left to each project?
- Migration order: which existing Neko\* project should be first to switch over to this server, once Phase 7's SDK exists?
- VRChat bot connector (Phase 4): reuse `VRCLogger/BACKEND` as the bot service, or stand up an independent one owned by this project?
- Email (Phase 6): is SMTP-only sufficient long-term, or will a hosted provider (SendGrid/Mailgun) be needed for deliverability at scale? The connector interface should stay pluggable either way.
