import Provider from "oidc-provider";
import { config } from "../config.js";
import { adapterFactory } from "./adapter.js";

// NOTE: no `jwks` is configured, so oidc-provider auto-generates an ephemeral
// dev keystore on every restart (logged as a "NOT SECURE FOR PRODUCTION"
// warning). Persisting a real, rotatable JWKS is Phase 2's job.
export const oidcProvider = new Provider(config.issuer, {
  adapter: adapterFactory,
  cookies: {
    keys: [process.env.COOKIE_SECRET ?? "dev-insecure-cookie-secret-change-me"],
  },
  // `pkce` is a top-level Configuration key, not a `features` flag — confirmed
  // against the installed package's own source (lib/helpers/defaults.js).
  pkce: {
    // Require PKCE from every client, including confidential ones — not
    // just the public-client default RFC 9700 already mandates. This is a
    // policy about clients connecting to *this* server; it says nothing
    // about the upstream connectors this server acts as a client to in
    // Phase 4 (see TODO.md's note there).
    required: () => true,
  },
  claims: {
    openid: ["sub"],
    profile: ["name", "picture"],
    email: ["email", "email_verified"],
  },
});

oidcProvider.on("server_error", (_ctx, err) => {
  console.error("oidc-provider server_error:", err);
});
