import "dotenv/config";

// Generate with `pnpm --filter server generate:jwks` and set as JWKS in .env.
// Left undefined in dev if unset — oidc-provider then auto-generates an
// ephemeral keypair (logged as "NOT SECURE FOR PRODUCTION") that changes on
// every restart. See scripts/generate-jwks.ts for the rotation procedure.
const jwks = process.env.JWKS ? JSON.parse(process.env.JWKS) : undefined;

export const config = {
  port: Number(process.env.PORT ?? 4000),
  nodeEnv: process.env.NODE_ENV ?? "development",
  issuer: process.env.ISSUER ?? "http://localhost:4000/oidc",
  jwks,
};
