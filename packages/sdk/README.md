# @nekosunevr/oauth2-sdk

Client SDK for logging a Neko\* Express app into [NekoOAuth2Server](../../README.md) — one shared identity server instead of every project registering its own Discord OAuth app.

## Add login to a new project in under 10 minutes

1. **Install it.** Not published yet (see the server repo's TODO.md Phase 7), so point at it directly:
   ```json
   "dependencies": {
     "@nekosunevr/oauth2-sdk": "file:../relative/path/to/NekoOAuth2Server/packages/sdk"
   }
   ```
   Run `npm install` (or `pnpm install`). Requires the SDK's `dist/` to already be built — `pnpm --filter sdk build` in the server repo.

2. **Register your app as a Client** on NekoOAuth2Server (via `prisma`/the future admin console — see the server repo's Phase 8) with:
   - a `redirectUris` entry matching where you'll mount the callback route, e.g. `http://localhost:3000/auth/neko/callback`
   - `isConfidential: false` / `tokenEndpointAuthMethod: "none"` unless you specifically want a confidential client

3. **Wire it into your Express app** (`express-session`, or a compatible session middleware, must already be configured — the SDK stores its state on `req.session`, it doesn't ship its own store):
   ```js
   import { createNekoAuthClient } from "@nekosunevr/oauth2-sdk";
   import { createExpressAuth, requireAuth } from "@nekosunevr/oauth2-sdk/express";

   const client = createNekoAuthClient({
     issuer: process.env.NEKO_OAUTH_ISSUER, // e.g. "http://localhost:4000/oidc"
     clientId: process.env.NEKO_OAUTH_CLIENT_ID,
     redirectUri: process.env.NEKO_OAUTH_REDIRECT_URI, // e.g. "http://localhost:3000/auth/neko/callback"
   });

   app.use(createExpressAuth(client)); // mounts /auth/login, /auth/callback, /auth/logout by default
   app.get("/protected", requireAuth(), (req, res) => {
     res.json({ user: req.nekoUser }); // { sub, profile, accessToken, refreshToken?, expiresAt? }
   });
   ```
   A CommonJS app can't `require()` this package directly (it's ESM-only) — use a dynamic `import()` once at startup instead. See the real worked example below.

4. **Handle the `user.deleted` webhook** (so deleting an account on NekoOAuth2Server actually removes it from your app too):
   ```js
   import { createWebhookMiddleware } from "@nekosunevr/oauth2-sdk/express";
   app.post(
     "/webhooks/neko",
     express.raw({ type: "application/json" }), // NOT express.json() — the signature is over the raw bytes
     createWebhookMiddleware(process.env.NEKO_WEBHOOK_SECRET, async (event) => {
       if (event.event === "user.deleted") {
         // purge your own cached copy of event.data.sub
       }
     }),
   );
   ```

## Real worked example

`API/V5/V5_UNIFIED` (a real, separate Neko\* project) was migrated off a direct `passport-discord` strategy to this SDK as the first real integration test — see its `src/config/nekoAuth.js`, `src/app.js`, and `src/routes/auth.js` for a complete example of the CJS/dynamic-`import()` pattern, and how to adapt the SDK's result into an app's *existing* session/identity system (there, Passport) instead of replacing it outright. Verified end to end against a real, live NekoOAuth2Server instance — real login, real code exchange, real id_token verification, a real local user row created and signed in.

## What's in here

- **Core** (`.`): `createNekoAuthClient`, PKCE helpers, discovery, webhook verification — framework-agnostic, no Express dependency.
- **Express** (`./express`): `createExpressAuth`, `requireAuth`, `createWebhookMiddleware` — everything above, wired to `req.session`.

See the source files' own doc comments for the full API; it's small enough that the code is the reference.
