# NekoOAuth2Server — Roadmap / TODO

This is the working plan for building NekoOAuth2Server: a self-hosted OIDC/OAuth 2.1 identity provider — Logto-inspired, but self-built — meant to be the *one* login server every Neko\* project federates through, instead of each project running its own separate Discord OAuth app and disconnected user table.

Legend: `[ ]` not started · `[~]` in progress · `[x]` done

---

## Phase 0 — Planning & Decisions

- [x] Write initial README.md, TODO.md
- [x] Decide project license → **AGPL-3.0**. This server holds auth secrets and user data for every other Neko\* project; the network-use clause means anyone who forks this and runs a modified version as a hosted service has to release their changes too — closes the "quietly resell my work" loophole plain GPL leaves open for server software.
- [x] Decide core language/runtime → **Node.js + TypeScript**, confirmed after auditing every other Neko\* web project. Node/TS is used in 14 of 15 surveyed projects; it's the only realistic choice for staying consistent with the rest of the ecosystem this server has to interoperate with.
- [x] Decide database → **PostgreSQL** (not the more common MySQL/MariaDB seen across older Neko\* projects) — better fit for the JSON columns, row-level constraints, and relational RBAC/multi-tenancy data this project actually needs, and it's what Logto itself uses.
- [x] Decide repo layout → **pnpm monorepo**: `apps/server` (OIDC core), `apps/console` (admin dashboard, added when Phase 7 starts), `packages/shared` (types/schemas), `packages/sdk` (client library for downstream Neko\* apps to consume) — same shape as `account-recovery-keychain`.
- [x] Decide how to build the OIDC/OAuth core → **do not hand-roll authorization-code/PKCE/JWT crypto from scratch.** Build on a mature, widely-audited Node OIDC provider library and put the "own version" effort into the data model, multi-tenancy, RBAC, admin console, and downstream SDK instead. A bug in hand-rolled token-signing code would compromise every federated Neko\* site at once — this is the one place where "reuse a proven library" clearly beats "build it myself," the same reasoning NekoDL used for BitTorrent/Mega.nz crypto rather than the WebSocket handshake it did hand-roll.
- [ ] Pick the specific OIDC provider library to build on (leading candidate: `panva/oidc-provider` — certified OIDC Provider, actively maintained, Postgres-friendly custom adapter support) — confirm before Phase 1 starts.
- [ ] Decide on ORM → leaning **Prisma** (matches the newest/most security-conscious Neko\* project, `account-recovery-keychain`) over Sequelize (the older house default) — confirm when Phase 1 starts.
- [ ] Decide the shape of the "shared identity" data model — what profile fields are common across all Neko\* projects vs. per-project, and what a downstream app can read via scope-gated consent vs. never.

## Phase 1 — Core Server Skeleton

- [x] Scaffold `apps/server` — minimal Express + TypeScript app with a `/health` endpoint, env-based config, and a build/dev script. No OIDC logic yet — just proves the workspace boots.
- [ ] Set up Prisma + PostgreSQL connection, initial migration (empty/placeholder schema)
- [ ] Wire chosen OIDC provider library into `apps/server`, backed by a custom Postgres storage adapter (not the library's default in-memory/redis adapter)
- [ ] Define initial data model: `Tenant`, `Client` (per-project OAuth app registration), `User`, `Session`
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
- [ ] Role/permission schema, scoped per client application
- [ ] Enforce RBAC checks in issued token claims and on the admin API
- [ ] Tests: a user with role X in Project A cannot use that role's permissions when authenticating to Project B

## Phase 4 — SSO / Upstream Social Login

- [ ] Discord upstream connector (highest priority — every existing Neko\* site already depends on Discord login)
- [ ] Normalize upstream profile data into this server's own `User` model, not passed through raw
- [ ] Google connector
- [ ] GitHub connector
- [ ] Document the connector plugin interface so more providers can be added without touching core (mirrors NekoDL's resolver-plugin pattern)

## Phase 5 — Shared Identity / Central Profile Store

- [ ] Define which profile fields are global (shared across every Neko\* project) vs. per-project-only
- [ ] Consent screen: a downstream app requesting a new scope shows the user exactly what data it's asking for
- [ ] API for a downstream app to read/update the shared profile fields it's been granted scope for
- [ ] Migration plan: how existing per-project user tables (Discord ID, etc.) map onto the new shared identity when a site adopts this server

## Phase 6 — Client SDK for Downstream Neko\* Apps

- [ ] `packages/sdk` — thin library wrapping: redirect-to-login, PKCE code_verifier generation/storage, token exchange, JWKS-based token verification, shared-profile fetch
- [ ] Framework-agnostic core + a small Express middleware helper (since Express is the dominant framework across existing Neko\* sites)
- [ ] Migrate one real existing Neko\* project (candidate: a site currently using Passport + Discord OAuth directly) to use this SDK, end to end, as the first real integration test
- [ ] Document the "how to add login to a new Neko\* project in under 10 minutes" flow

## Phase 7 — Admin Console

- [ ] Scaffold `apps/console` (Next.js, matching `account-recovery-keychain`'s precedent)
- [ ] Manage clients (register a new downstream project, rotate its secret)
- [ ] Manage users, roles, sessions (view + force-revoke)
- [ ] Audit log viewer

## Phase 8 — Security Hardening & Audit Logging

- [ ] Structured audit log for every login, token issuance/revocation, and admin action
- [ ] Rate limiting on token/authorize endpoints
- [ ] Session/device management for end users (list active sessions, "log out everywhere")
- [ ] Secret handling review: client secrets, signing keys, upstream provider credentials — never logged, encrypted at rest
- [ ] Security review pass before any real project migrates over (see `account-recovery-keychain`'s security-model write-up for the bar to hit)

## Phase 9 — Docker & Deployment

- [ ] `Dockerfile` (multi-stage: build, slim runtime, non-root user)
- [ ] `docker-compose.yml` (server + PostgreSQL, and console once Phase 7 lands)
- [ ] Document required environment variables and config precedence
- [ ] Health checks + graceful shutdown
- [ ] Backup/restore plan for the Postgres database (this becomes the single source of truth for auth across every project — losing it is not a "restart the container" problem)

## Phase 10 — Docs & Public Release

- [ ] Finalize README (replace "early planning" status once Phase 1–2 are real)
- [ ] Per-project integration guide using the Phase 6 SDK
- [ ] CONTRIBUTING.md
- [ ] Tag v0.1.0, set up CI (build/lint/test)

---

## Open Questions

- Single shared tenant for all first-party Neko\* projects, or one tenant per project from day one? Affects Phase 3's isolation model.
- Should this server also issue API keys for pure machine-to-machine Neko\* integrations (e.g. bot-to-bot), or is that out of scope and left to each project?
- Migration order: which existing Neko\* project should be first to switch over to this server, once Phase 6's SDK exists?
