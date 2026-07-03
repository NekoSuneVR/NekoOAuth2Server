import type { DefaultSession } from "next-auth";

declare module "next-auth" {
  interface Session extends DefaultSession {
    accessToken?: string;
    roles: string[];
    permissions: string[];
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string;
    roles?: string[];
    permissions?: string[];
  }
}
