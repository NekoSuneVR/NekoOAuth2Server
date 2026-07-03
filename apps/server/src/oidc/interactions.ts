import bcrypt from "bcryptjs";
import express, { Router } from "express";
import { connectorRegistry } from "../connectors/registry.js";
import { generatePkcePair } from "../connectors/pkce.js";
import { signUpstreamState, verifyUpstreamState } from "../connectors/state.js";
import { prisma } from "../db.js";
import { config } from "../config.js";
import { oidcProvider } from "./provider.js";

// Deliberately minimal, unstyled HTML — this proves the OIDC interaction
// flow (login + consent) actually works end to end. A real sign-in/consent
// UI is Phase 8's job; this is not it.
const body = express.urlencoded({ extended: false });

export const interactionsRouter = Router();

// Redirect URIs registered with upstream providers need to be stable, so
// this is derived from our own configured issuer (which is meant to be this
// server's real, constant public identity), not the incoming request's Host
// header — a proxied/spoofed Host shouldn't be able to influence what we
// tell a third party to redirect back to.
function upstreamCallbackUrl(uid: string, providerId: string) {
  const issuerUrl = new URL(config.issuer);
  return `${issuerUrl.protocol}//${issuerUrl.host}/oidc/interaction/${uid}/upstream/${providerId}/callback`;
}

interactionsRouter.get("/interaction/:uid", async (req, res, next) => {
  try {
    const { uid, prompt, params } = await oidcProvider.interactionDetails(req, res);

    if (prompt.name === "login") {
      const upstreamLinks = [...connectorRegistry.keys()]
        .map((id) => `<a href="/oidc/interaction/${uid}/upstream/${id}">Sign in with ${id}</a>`)
        .join(" · ");

      res.type("html").send(`
        <h1>Sign in</h1>
        <form method="post" action="/oidc/interaction/${uid}/login">
          <input type="email" name="email" placeholder="Email" required />
          <input type="password" name="password" placeholder="Password" required />
          <button type="submit">Sign in</button>
        </form>
        ${upstreamLinks ? `<p>${upstreamLinks}</p>` : ""}
      `);
      return;
    }

    if (prompt.name === "consent") {
      const details = prompt.details as Record<string, unknown>;
      res.type("html").send(`
        <h1>Authorize ${String(params.client_id)}</h1>
        <pre>${JSON.stringify(details, null, 2)}</pre>
        <form method="post" action="/oidc/interaction/${uid}/confirm">
          <button type="submit">Allow</button>
        </form>
        <a href="/oidc/interaction/${uid}/abort">Deny</a>
      `);
      return;
    }

    next(new Error(`unsupported prompt: ${prompt.name}`));
  } catch (err) {
    next(err);
  }
});

interactionsRouter.post("/interaction/:uid/login", body, async (req, res, next) => {
  try {
    const { prompt } = await oidcProvider.interactionDetails(req, res);
    if (prompt.name !== "login") throw new Error("not a login prompt");

    const { email, password } = req.body as { email?: string; password?: string };
    const user = email ? await prisma.user.findUnique({ where: { primaryEmail: email } }) : null;
    const valid = user?.passwordHash && password ? await bcrypt.compare(password, user.passwordHash) : false;

    if (!user || !valid) {
      res.status(401).type("html").send("<p>Invalid email or password.</p>");
      return;
    }

    await oidcProvider.interactionFinished(
      req,
      res,
      { login: { accountId: user.id } },
      { mergeWithLastSubmission: false },
    );
  } catch (err) {
    next(err);
  }
});

interactionsRouter.post("/interaction/:uid/confirm", body, async (req, res, next) => {
  try {
    const interactionDetails = await oidcProvider.interactionDetails(req, res);
    const { prompt, params, session } = interactionDetails;
    if (prompt.name !== "consent") throw new Error("not a consent prompt");
    if (!session) throw new Error("no session for consent step");

    const details = prompt.details as {
      missingOIDCScope?: string[];
      missingOIDCClaims?: string[];
      missingResourceScopes?: Record<string, string[]>;
    };

    let { grantId } = interactionDetails;
    const grant = grantId
      ? await oidcProvider.Grant.find(grantId)
      : new oidcProvider.Grant({ accountId: session.accountId, clientId: params.client_id as string });

    if (!grant) throw new Error(`grant ${grantId} not found`);

    if (details.missingOIDCScope) grant.addOIDCScope(details.missingOIDCScope.join(" "));
    if (details.missingOIDCClaims) grant.addOIDCClaims(details.missingOIDCClaims);
    if (details.missingResourceScopes) {
      for (const [indicator, scopes] of Object.entries(details.missingResourceScopes)) {
        grant.addResourceScope(indicator, scopes.join(" "));
      }
    }

    grantId = await grant.save();

    const consent: { grantId?: string } = {};
    if (!interactionDetails.grantId) consent.grantId = grantId;

    await oidcProvider.interactionFinished(req, res, { consent }, { mergeWithLastSubmission: true });
  } catch (err) {
    next(err);
  }
});

interactionsRouter.get("/interaction/:uid/abort", async (req, res, next) => {
  try {
    await oidcProvider.interactionFinished(
      req,
      res,
      { error: "access_denied", error_description: "End-User aborted interaction" },
      { mergeWithLastSubmission: false },
    );
  } catch (err) {
    next(err);
  }
});

interactionsRouter.get("/interaction/:uid/upstream/:providerId", async (req, res, next) => {
  try {
    const { prompt } = await oidcProvider.interactionDetails(req, res);
    if (prompt.name !== "login") throw new Error("not a login prompt");

    const connector = connectorRegistry.get(req.params.providerId);
    if (!connector) {
      res.status(404).json({ error: "unknown_provider" });
      return;
    }

    const codeVerifier = connector.pkce === "unsupported" ? undefined : generatePkcePair().verifier;
    const state = signUpstreamState({ uid: req.params.uid, provider: req.params.providerId, codeVerifier });

    const authorizationUri = connector.getAuthorizationUri({
      state,
      redirectUri: upstreamCallbackUrl(req.params.uid, req.params.providerId),
      codeVerifier,
    });
    res.redirect(authorizationUri);
  } catch (err) {
    next(err);
  }
});

interactionsRouter.get("/interaction/:uid/upstream/:providerId/callback", async (req, res, next) => {
  try {
    const connector = connectorRegistry.get(req.params.providerId);
    if (!connector) {
      res.status(404).json({ error: "unknown_provider" });
      return;
    }

    const { uid, provider, codeVerifier } = verifyUpstreamState(String(req.query.state));
    if (uid !== req.params.uid || provider !== req.params.providerId) {
      throw new Error("upstream state does not match this interaction/provider");
    }

    const tokens = await connector.exchangeCode({
      code: String(req.query.code),
      redirectUri: upstreamCallbackUrl(uid, provider),
      codeVerifier,
    });
    const info = await connector.getUserInfo(tokens);

    const existingLink = await prisma.linkedIdentity.findUnique({
      where: { provider_providerUserId: { provider, providerUserId: info.id } },
    });

    let userId: string;
    if (existingLink) {
      userId = existingLink.userId;
    } else {
      // Same email as an existing account (e.g. previously registered with a
      // password) links to that account instead of creating a duplicate one.
      const existingUser = info.email
        ? await prisma.user.findUnique({ where: { primaryEmail: info.email } })
        : null;
      const user =
        existingUser ??
        (await prisma.user.create({
          data: {
            primaryEmail: info.email,
            emailVerified: Boolean(info.email),
            displayName: info.username,
          },
        }));

      await prisma.linkedIdentity.create({
        data: {
          userId: user.id,
          provider,
          providerUserId: info.id,
          providerUsername: info.username,
          verifiedVia: "oauth",
        },
      });
      userId = user.id;
    }

    await oidcProvider.interactionFinished(req, res, { login: { accountId: userId } }, { mergeWithLastSubmission: false });
  } catch (err) {
    next(err);
  }
});
