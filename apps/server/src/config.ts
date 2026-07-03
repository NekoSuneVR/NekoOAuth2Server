import "dotenv/config";

export const config = {
  port: Number(process.env.PORT ?? 4000),
  nodeEnv: process.env.NODE_ENV ?? "development",
  issuer: process.env.ISSUER ?? "http://localhost:4000/oidc",
};
