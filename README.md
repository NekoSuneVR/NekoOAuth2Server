# NekoOAuth2Server

🧑‍🚀 A self-hosted, security-first identity provider for every Neko\* project — one OIDC / OAuth 2.1 server instead of twenty copy-pasted Discord OAuth apps.

> **Status: early planning / scaffold.** Nothing in the "Planned features" list below is implemented yet. This README describes the target design; see [TODO.md](TODO.md) for what's actually done versus still to build.

## Why this exists

Right now, every new Neko\* site registers its own Discord OAuth2 app, stores its own copy of user data, and re-implements login from scratch. That means:

- N separate Discord (and eventually Google/GitHub/etc.) app registrations to keep in sync
- N separate places a session/token bug can happen
- No single "this is the same person" identity across projects — each site's user table is an island

NekoOAuth2Server is meant to fix that: **one OIDC/OAuth 2.1 provider that every other Neko\* project logs in through.** A user authenticates once, and any of my other apps can accept that same identity (and pull shared profile data) via standard OIDC — no more per-project OAuth app sprawl.

This is deliberately modeled on what [Logto](https://github.com/logto-io/logto) does architecturally (OIDC core + admin console + multi-tenant RBAC + social connectors), but self-hosted, self-built, and tuned for how the Neko\* projects actually need to consume it.

## Planned features

- **OIDC provider + OAuth 2.1** — authorization code flow with **mandatory PKCE** (`code_verifier`/`code_challenge`) on every client, refresh token rotation, client credentials for service-to-service calls
- **Multi-tenancy** — one deployment, many isolated "organizations" if ever needed, without becoming a requirement for the common case (a handful of trusted first-party apps)
- **RBAC** — roles/permissions scoped per client application, checked via token claims/scopes
- **SSO / upstream social login** — Discord first (since every existing Neko\* site already uses it), Google/GitHub as later connectors, all normalized behind this server so downstream apps only ever speak OIDC to *this* server, never to Discord directly
- **One identity, shared profile data** — a central user record that downstream apps can pull from (with consent/scopes), instead of every site keeping its own disconnected copy. A user can link multiple platforms (Discord, VRChat, Twitch, Roblox, etc.) to one account, and deleting that account propagates a signed deletion event to every downstream app so their cached copy of that user's data actually gets removed too
- **Platforms without OAuth2 still supported** — VRChat has no public OAuth2, so it gets its own bot-verified connector (bio-code or friend-request verification, the same proven pattern already used in `SocialLinkUpOnly`) instead of being left out
- **Transactional email** — SMTP-based, template-driven (sign-in codes, password reset, MFA, invitations, etc.)
- **Admin console** — manage clients (per-project OAuth apps), users, roles, and sessions without hand-editing the database
- **Session & device management, audit log** — every login/token event traceable, sessions individually revocable

## Security model (honest, up front)

This server will be the single point of failure for authentication across *every* Neko\* project — a bug here is worse than a bug in any one downstream app, because it compromises all of them at once. Given that:

- The crypto-sensitive core (authorization code exchange, PKCE verification, JWT signing/rotation, JWKS) is planned to be built on top of a mature, widely-audited OIDC library rather than hand-rolled from scratch. Hand-rolling raw OAuth/OIDC cryptography has a long history of subtle, exploitable bugs; the "own version" part of this project is the data model, multi-tenancy, RBAC, admin console, and how downstream Neko\* apps integrate — not reinventing token signing.
- PKCE will be **required**, not optional, for every client type, including confidential clients — closing the class of authorization-code-interception attacks PKCE exists to prevent.
- No claims of "unhackable" will ever go in this README. See [TODO.md](TODO.md) for what's actually been built and verified versus still planned.

## Planned architecture

```
NekoOAuth2Server/
  apps/
    server/     # OIDC/OAuth 2.1 core — Node.js + TypeScript + Express, PostgreSQL via Prisma
    console/    # Admin dashboard for managing clients/users/roles (planned, Phase 7)
  packages/
    shared/     # Shared TypeScript types + validation schemas (Tenant, Client, User, Role, Token claims)
    sdk/        # Thin client library other Neko* sites import to log in against this server and read shared profile data
```

## Getting started

Only the bare workspace + a minimal `apps/server` health-check scaffold exist right now — this is not yet a working OAuth server.

```bash
pnpm install
pnpm --filter server dev
```

## Roadmap

See [TODO.md](TODO.md) for the phased build plan and current progress.

## License

[GNU AGPL-3.0](LICENSE). This project handles authentication for other projects and stores user data — the AGPL's network-use clause means if anyone runs a modified version of this as a service, they have to release their source changes too. That's a deliberate choice to keep this code (and any forks of it) open, not something anyone can quietly take, close up, and resell.
