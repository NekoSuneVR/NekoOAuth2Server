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
- [x] `docker-compose.dev.yml` (repo root) for **local dev only** — Postgres 16 + adminer, matching the credentials in `.env.example` — separate from the full production Docker setup in Phase 10.
- [x] Prisma schema (`apps/server/prisma/schema.prisma`): `Tenant`, `Client`, `User`, `LinkedIdentity`, `ClientConsent` per Phase 0's data model, plus `OidcModel` — a generic key/value table backing every oidc-provider model *except* Client (Session, AccessToken, AuthorizationCode, RefreshToken, Grant, Interaction, etc. all share it, namespaced by `type`), the standard pattern for SQL-backed oidc-provider adapters rather than one bespoke table per model. There's no separate `Session` table — oidc-provider's "Session" model is one more `type` row in `OidcModel`, not a hand-rolled concept of our own.
  - One real correction made along the way: the original plan said `clientSecretHash`. Renamed to plain `clientSecret` — oidc-provider's built-in `client_secret_basic`/`client_secret_post` verification does a constant-time comparison against the *raw* configured secret, so a one-way hash would silently break auth. Noted in the schema and flagged for Phase 9 to revisit as reversible envelope encryption at rest instead.
  - Migration SQL generated and committed at `apps/server/prisma/migrations/20260101000000_init/`.
- [x] Wired `oidc-provider` (`panva/oidc-provider`, per Phase 0) into `apps/server` (`src/oidc/provider.ts`), with a custom adapter (`src/oidc/adapter.ts`) — `oidcModelAdapter.ts` implements the generic `OidcModel`-table adapter (upsert/find/findByUid/findByUserCode/consume/destroy/revokeByGrantId, mirroring oidc-provider's own memory adapter), and `clientAdapter.ts` overrides just the `Client` model to read from our own `Client` table instead, so the admin console (Phase 8) will CRUD real columns rather than JSON blobs.
- [x] PKCE required for every client type, including confidential ones — `pkce: { required: () => true }` (a top-level `Configuration` key, not a `features` flag — the installed library's own source was checked directly after `@types/oidc-provider@9.5.0` turned out not to type it). **Verified with a real, passing 7-test suite** (`src/oidc/pkce.test.ts`, supertest against `oidcProvider.callback()`), not just configured and assumed correct:
  - a public client's `/auth` request with no `code_challenge` is rejected (`invalid_request`, "policy requires PKCE")
  - a **confidential** client's `/auth` request with no `code_challenge` is *also* rejected — the actual point of this policy, since RFC 9700 alone wouldn't require it for confidential clients
  - a request that *does* supply a valid `code_challenge` proceeds normally (positive control — proves the check is specifically about PKCE, not blocking everything)
  - a code exchange with the wrong `code_verifier` is rejected (`invalid_grant`)
  - a code exchange with no `code_verifier` at all is rejected (`invalid_grant`)
  - a code exchange with the **correct** `code_verifier` succeeds and returns a real `access_token` — proving the mechanism actually works end-to-end, not just that it always errors
  - the confidential-client code path is independently re-checked at the token endpoint too
  - One real bug the test suite caught in itself: the first "wrong code_verifier" attempt used a hand-typed 42-character string, one short of RFC 7636's 43-character minimum, so oidc-provider correctly rejected it as a format error (`invalid_request`) rather than reaching the semantic mismatch check (`invalid_grant`) the test meant to exercise. Fixed by generating the wrong verifier the same way as a real one (`crypto.randomBytes(32).toString("base64url")`), just discarded rather than used for the challenge.

**A note on how this was verified, in the interest of honesty**: this sandbox has no Docker and no local Postgres install. Schema and query-level verification (does the schema apply, do the adapter's queries round-trip correctly, does the PKCE policy actually behave as configured) was done against [`@electric-sql/pglite`](https://github.com/electric-sql/pglite) — a real Postgres engine compiled to WASM, wire-compatible enough for `prisma db push` and the full application/test stack — proxied over TCP via `@electric-sql/pglite-socket` so the standard `postgresql://` connection string worked unmodified. Neither package is a dependency of the project itself; they only ever ran in a scratch directory outside the repo. `prisma migrate dev` itself doesn't work against it (it needs a shadow database via `CREATE DATABASE`, which this single-logical-database engine doesn't support), so the committed migration SQL was instead generated with `prisma migrate diff --from-empty` — a schema-only diff that needs no live database — and its correctness was separately confirmed by watching `db push` apply that identical schema cleanly. The one thing **not** re-verified here is the real `docker-compose.dev.yml` path itself (no Docker daemon available) — worth a quick real run before this is treated as fully proven on a normal dev machine.

**Update from Phase 2**: this substitute has a real limit worth knowing about — under the heavier, multi-hop HTTP traffic of `e2e.test.ts`'s 9 tests, it reliably degrades enough that whichever test file runs *after* it in the same `vitest` process fails to connect at all. Both `pkce.test.ts` and `e2e.test.ts` pass 100% individually against a freshly restarted instance; it's specifically the combined-in-one-process, heavy-load case that's unreliable. This reads as a connection-handling limit of the pglite socket multiplexer, not a product bug — but it's also a real signal that this substitute has reached the edge of what it's good for. Real Postgres via `docker-compose.dev.yml` is worth switching to for any further phases' verification.

## Phase 2 — OAuth 2.1 / OIDC Compliance

- [x] **Authorization code flow, end to end, against a real test client** — driven over real HTTP (`src/oidc/e2e.test.ts`), not internal-model shortcuts: `/oidc/auth` → our own login form → our own consent form → redirect back to the client with a code → `/oidc/token` exchange → real `access_token`/`id_token`. This required building a real (if deliberately unstyled) interaction UI, since `oidc-provider`'s built-in `devInteractions` is explicitly "not for production" — see the new `src/oidc/interactions.ts` and `src/oidc/provider.ts`'s `findAccount` (backed by Prisma, needs a real `User.passwordHash` — added to the schema, see Phase 0's note on this being a placeholder baseline credential, not a final decision on end-user auth). **This exposed a real gap in the roadmap**: there was no phase covering the end-user sign-in/consent UI at all (Phase 8 only covers the *admin* console). The interaction routes built here are functional but intentionally minimal/unstyled; a real sign-in experience is still open — see Open Questions.
- [x] **Refresh token rotation with reuse detection** — no custom config needed: `oidc-provider`'s default `rotateRefreshToken` policy already rotates every refresh token for public clients unconditionally. **Verified with a real 3-step replay test**: use refresh token #1 → get a new refresh token #2 (rotation confirmed by the two values differing) → replay the now-consumed #1 → rejected (`invalid_grant`) → then try the legitimately-rotated #2 → *also* rejected. That last step is the one that actually proves "revokes the whole token family," not just "the specific replayed token is dead."
- [x] **Client credentials flow for service-to-service calls** — `features.clientCredentials.enabled: true`, plus one real resource indicator (`INTERNAL_API_RESOURCE`, a placeholder identifier standing in for "some future Neko\* backend API") wired through `features.resourceIndicators.getResourceServerInfo`. Verified both with and without an explicit `resource` parameter — a client_credentials token doesn't require one at all if the caller just wants an unscoped-to-any-API token.
- [x] **JWKS endpoint + key rotation strategy** — `scripts/generate-jwks.ts` generates a real persistent RS256 keypair (set as the `JWKS` env var); without it the server falls back to an ephemeral dev keystore that changes every restart (fine for local dev, breaks anything relying on a stable key in real use). **Rotation strategy is manual, not automated**: add a new key alongside the old one in the `keys` array (never replace outright) so tokens signed with the old key keep verifying until every token issued under it has expired, then remove the old key. No scheduler exists to do this automatically yet — that's real future work, not implied by what's here.
- [x] **Discovery document** — already live since Phase 1; this phase specifically verified completeness (`grant_types_supported`, `code_challenge_methods_supported`, `scopes_supported`, `claims_supported`, etc.) rather than just that the endpoint responds. **One real, non-obvious behavior found while testing this**: `authorization_endpoint`/`token_endpoint`/`jwks_uri` are host-qualified using the *serving request's* Host header, not statically fixed to the configured issuer string — correct behavior for reverse-proxy-friendly deployments, but it means naive tests (or naive downstream clients) asserting an exact static URL for these will be wrong; only `issuer` itself is the static, configured value.
- [x] **Scope/claims model** — `openid`/`profile`/`email` claims configured, plus two resource-specific scopes (`internal:read`/`internal:write`) for the client-credentials resource above. **Real, confirmed distinction**: profile/email claims are delivered via the `/oidc/me` userinfo endpoint when requested with an access token, *not* embedded in the code-flow `id_token` (which only carries `sub` by default) — verified by actually calling `/oidc/me` and checking claims appear/disappear based on granted scope, not by inspecting the id_token (an earlier version of this test checked the wrong place and looked like it passed for the wrong reason).

**Bugs this phase's real testing caught (all fixed, not glossed over):**
- Setting a custom `scopes: [...]` config array to register `internal:read`/`internal:write` **replaced**, rather than extended, `oidc-provider`'s default `['openid', 'offline_access']` — which silently disabled the `refresh_token` grant entirely (it's only enabled when `'offline_access'` is present in that exact list) and broke every client whose registered `grant_types` included `refresh_token`. Caught by the client-metadata-validation error itself (`grant_types can only contain 'implicit', 'authorization_code', 'client_credentials'`), not by guessing — fixed by including the defaults explicitly alongside the new scopes.
- The planned `User.clientSecretHash`-style thinking almost repeated itself here: `Client.scope` (a client's *allowed-to-request* scopes) and a resource server's *own* granted scopes (`getResourceServerInfo`'s return value) are two separate validation layers — a scope has to be recognized in both places, not just one.
- `pkce.test.ts` (Phase 1) started failing after `findAccount` was wired up for real: it used a fabricated `accountId` string that was never a real `User` row, which worked when `findAccount` was still `oidc-provider`'s default passthrough (accepts any id) but broke once a real Prisma-backed lookup replaced it. Fixed by seeding a real test `User` and referencing its actual id — arguably a more correct test than before, not just a patch.

## Phase 3 — Multi-Tenancy & RBAC

- [ ] Tenant isolation model (decide: fully isolated orgs, or a single "Neko" tenant with per-client scoping — revisit Phase 0's open question once real usage patterns are clearer)
- [ ] Role/permission schema, scoped per client application (and, if useful, per-organization along Logto's "organization template" shape — one shared role/permission set, different assignments per org)
- [ ] Enforce RBAC checks in issued token claims and on the admin API
- [ ] Tests: a user with role X in Project A cannot use that role's permissions when authenticating to Project B

## Phase 4 — SSO / Upstream Connectors

**Architecture**: two generic, config-driven connector types (see Phase 0 decision) implementing one shared interface — `getAuthorizationUri`, `authorizationCallbackHandler`, `getAccessToken`, `getUserInfo` — plus one genuinely custom connector type for platforms with no OAuth2 at all.

- [ ] Build the **generic OAuth 2.0 connector** type: config = authorization URL, token URL, userinfo URL, `client_id`/`client_secret`, scopes, PKCE method. **PKCE support varies per upstream provider — don't hardcode it as always-on.** Some providers require it (VPZone: mandatory `S256`), some support it optionally (most modern providers), and some older/simpler OAuth2 implementations don't support the `code_challenge`/`code_verifier` params at all and may error if they're sent. The per-provider config needs a tri-state `pkce: "required" | "optional" | "unsupported"`, not a single global assumption — this is separate from, and doesn't affect, Phase 1's decision that *our own* server always requires PKCE from clients connecting to *us*.
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
- **New, found during Phase 2**: is email+password the real, permanent baseline sign-in method, or purely a placeholder until social connectors (Phase 4) and/or magic-link email (Phase 6) exist? `User.passwordHash` was added to unblock testing the OAuth mechanics for real, not as a considered decision on end-user auth UX.
- **New, found during Phase 2**: there's no phase covering the end-user sign-in/consent *experience* — Phase 8 is the admin console only. The interaction routes built in Phase 2 (`src/oidc/interactions.ts`) are functional but deliberately unstyled. Worth a dedicated phase (mirroring Logto's separate `experience` package) once there's a real visual design to build to, rather than folding it unplanned into Phase 8's admin work.
