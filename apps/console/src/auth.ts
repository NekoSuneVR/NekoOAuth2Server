import NextAuth from "next-auth";

/**
 * Dogfoods the server this console administers: apps/console is itself
 * registered as a Client (clientId "neko-console", see apps/server's
 * prisma/seed.ts) and admins log in through the exact same OIDC flow every
 * other Neko* project uses. `type: "oidc"` makes Auth.js fetch our real
 * discovery document and do real PKCE + state checks against a mature,
 * independently-audited client library (openid-client) rather than us
 * hand-rolling a second OIDC relying party implementation in this app.
 */
export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    {
      id: "neko",
      name: "NekoOAuth2Server",
      type: "oidc",
      issuer: process.env.NEKO_OAUTH_ISSUER,
      clientId: process.env.NEKO_OAUTH_CLIENT_ID,
      clientSecret: process.env.NEKO_OAUTH_CLIENT_SECRET,
      authorization: { params: { scope: "openid profile email roles" } },
      // The server deliberately keeps id_token thin (only `sub` — see the
      // server repo's TODO.md Phase 2) and serves profile/roles/permissions
      // claims from the userinfo endpoint instead. Auth.js defaults to
      // reading `profile` off the id_token's own claims for OIDC providers,
      // which would silently make `profile.roles`/`profile.permissions`
      // always undefined; `idToken: false` makes it call userinfo instead,
      // matching what our server actually expects a client to do.
      idToken: false,
    },
  ],
  pages: {
    signIn: "/login",
  },
  session: { strategy: "jwt" },
  callbacks: {
    async jwt({ token, account, profile }) {
      if (account) {
        token.accessToken = account.access_token;
        const claims = profile as { roles?: string[]; permissions?: string[] } | undefined;
        token.roles = claims?.roles ?? [];
        token.permissions = claims?.permissions ?? [];
      }
      return token;
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken as string | undefined;
      session.roles = (token.roles as string[] | undefined) ?? [];
      session.permissions = (token.permissions as string[] | undefined) ?? [];
      return session;
    },
  },
});
