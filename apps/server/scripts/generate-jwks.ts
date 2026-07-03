import crypto from "node:crypto";

/**
 * Generates a persistent JWKS for signing tokens. Run once and store the
 * output as the JWKS env var — without it, oidc-provider auto-generates a
 * new ephemeral keypair on every restart, invalidating every previously
 * issued token and breaking JWKS-based verification for anyone caching keys.
 *
 * Key rotation: to rotate, generate a *new* key and add it to the `keys`
 * array alongside the current one (don't replace it) so tokens already
 * signed with the old key still verify against /oidc/jwks during the
 * rollover window. Only remove the old key once every token signed with it
 * is guaranteed expired (i.e. after the longest configured token TTL has
 * passed). There's no automated rotation scheduler yet — this is a manual
 * procedure for now.
 */
const { privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = privateKey.export({ format: "jwk" }) as Record<string, unknown>;

const kid = crypto.randomUUID();
const jwks = {
  keys: [{ ...jwk, kid, use: "sig", alg: "RS256" }],
};

console.log(JSON.stringify(jwks));
