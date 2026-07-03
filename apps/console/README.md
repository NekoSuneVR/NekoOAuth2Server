# NekoOAuth2Server Console

The admin console for [NekoOAuth2Server](../../README.md) — Next.js (App Router), Tailwind CSS v4, dark theme with a green accent, deliberately matching `account-recovery-keychain`'s exact design tokens rather than inventing a new palette (see `src/app/globals.css`).

**Status: client management only.** This console dogfoods the server it administers — it's registered as a real OAuth2 Client (`neko-console`) and admins log in through the exact same OIDC flow every other Neko\* project uses. Managing users/roles/sessions, the connector picker, the email template editor, webhook management, and an audit log viewer are all still ahead — see the server repo's [TODO.md](../../TODO.md) Phase 8.

## Local development

1. Get `apps/server` running first (see the [root README](../../README.md)) — this console has nothing to administer without it.
2. Run `pnpm --filter server prisma:seed` — seeds the `neko-console` Client and a `console-admin` role granting `admin:manage_clients` to `test@example.com` / `correct-horse-battery-staple`.
3. `cp .env.example .env.local` in this directory.
4. `pnpm --filter console dev` — runs on port 3001 (not 3000, so it doesn't collide with other local dev servers).
5. Sign in at `http://localhost:3001` with the seeded test account.

## How admin auth works

`src/auth.ts` configures NextAuth v5 (Auth.js) with a custom `type: "oidc"` provider pointed at the server's own issuer — Auth.js handles real discovery, PKCE, and state via `openid-client` under the hood, the same mature library approach the rest of this project takes toward OIDC/OAuth crypto (don't hand-roll it twice).

**One real, non-obvious thing this took live end-to-end testing to catch**: Auth.js defaults to reading the `profile` object (used to populate the JWT session) from the `id_token`'s own claims. NekoOAuth2Server deliberately keeps `id_token` thin — only `sub` — with `roles`/`profile`/`email` claims served from the userinfo endpoint instead (see the server repo's Phase 2 notes). Left at the default, `profile.roles`/`profile.permissions` were silently always `undefined`, and every login redirected to `/forbidden` even for a real admin. Fixed with `idToken: false` on the provider config, which makes Auth.js call userinfo instead — exactly what a compliant client should do against this server. This is the kind of bug that's invisible reading the code in isolation and only shows up by actually running the full login flow against a real server, which is how it was found.

Every admin API call (`src/lib/adminApi.ts`) happens server-side — Server Components and Server Actions calling `apps/server`'s `/api/admin/*` endpoints with the session's access token — never from browser-side JS, so the token never leaves the server.
