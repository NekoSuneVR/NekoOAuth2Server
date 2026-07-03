import bcrypt from "bcryptjs";
import express, { Router } from "express";
import { generatePkcePair } from "../connectors/pkce.js";
import { connectorRegistry } from "../connectors/registry.js";
import { signUpstreamState, verifyUpstreamState } from "../connectors/state.js";
import { getVRChatBotClient } from "../connectors/vrchat/clientProvider.js";
import { generateVerificationCode, verifyByBio, verifyByFriendRequest } from "../connectors/vrchat/verification.js";
import { config } from "../config.js";
import { prisma } from "../db.js";
import { deleteUserAccount } from "./deleteAccount.js";
import { clearAccountSession, getAccountSessionUserId, setAccountSession } from "./session.js";

const body = express.urlencoded({ extended: false });

export const accountRouter = Router();

function linkCallbackUrl(providerId: string) {
  const issuerUrl = new URL(config.issuer);
  return `${issuerUrl.protocol}//${issuerUrl.host}/account/link/${providerId}/callback`;
}

function requireSession(req: express.Request, res: express.Response): string | undefined {
  const userId = getAccountSessionUserId(req);
  if (!userId) {
    res.redirect("/account/login");
    return undefined;
  }
  return userId;
}

accountRouter.get("/login", (_req, res) => {
  res.type("html").send(`
    <h1>Sign in to your account</h1>
    <form method="post" action="/account/login">
      <input type="email" name="email" placeholder="Email" required />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Sign in</button>
    </form>
  `);
});

accountRouter.post("/login", body, async (req, res) => {
  const { email, password } = req.body as { email?: string; password?: string };
  const user = email ? await prisma.user.findUnique({ where: { primaryEmail: email } }) : null;
  const valid = user?.passwordHash && password ? await bcrypt.compare(password, user.passwordHash) : false;

  if (!user || !valid) {
    res.status(401).type("html").send("<p>Invalid email or password.</p>");
    return;
  }

  setAccountSession(res, user.id);
  res.redirect("/account");
});

accountRouter.get("/logout", (_req, res) => {
  clearAccountSession(res);
  res.redirect("/account/login");
});

accountRouter.get("/", async (req, res) => {
  const userId = requireSession(req, res);
  if (!userId) return;

  const user = await prisma.user.findUnique({ where: { id: userId }, include: { linkedIdentities: true } });
  if (!user) {
    clearAccountSession(res);
    res.redirect("/account/login");
    return;
  }

  const linkedProviders = new Set(user.linkedIdentities.map((li) => li.provider));
  const linkableProviders = [...connectorRegistry.keys()].filter((id) => !linkedProviders.has(id));

  const linkedRows = user.linkedIdentities
    .map(
      (li) => `<li>${li.provider}: ${li.providerUsername ?? li.providerUserId}
        <form method="post" action="/account/linked-identities/${li.id}/unlink" style="display:inline">
          <button type="submit">Unlink</button>
        </form>
      </li>`,
    )
    .join("");

  const linkLinks = linkableProviders.map((id) => `<a href="/account/link/${id}">Link ${id}</a>`).join(" · ");

  res.type("html").send(`
    <h1>Your account</h1>
    <p>Email: ${user.primaryEmail ?? "(none)"}</p>
    <p>Name: ${user.displayName ?? "(none)"}</p>

    <h2>Linked accounts</h2>
    <ul>${linkedRows || "<li>None yet.</li>"}</ul>
    ${linkLinks ? `<p>${linkLinks}</p>` : ""}
    <p><a href="/account/link/vrchat">Link VRChat</a></p>

    <form method="post" action="/account/delete" onsubmit="return confirm('Delete your account? This cannot be undone.')">
      <button type="submit">Delete my account</button>
    </form>
    <a href="/account/logout">Sign out</a>
  `);
});

accountRouter.get("/link/:providerId", async (req, res, next) => {
  try {
    const userId = requireSession(req, res);
    if (!userId) return;

    const connector = connectorRegistry.get(req.params.providerId);
    if (!connector) {
      res.status(404).json({ error: "unknown_provider" });
      return;
    }

    const codeVerifier = connector.pkce === "unsupported" ? undefined : generatePkcePair().verifier;
    const state = signUpstreamState({ mode: "link", userId, provider: req.params.providerId, codeVerifier });

    const authorizationUri = connector.getAuthorizationUri({
      state,
      redirectUri: linkCallbackUrl(req.params.providerId),
      codeVerifier,
    });
    res.redirect(authorizationUri);
  } catch (err) {
    next(err);
  }
});

accountRouter.get("/link/:providerId/callback", async (req, res, next) => {
  try {
    const connector = connectorRegistry.get(req.params.providerId);
    if (!connector) {
      res.status(404).json({ error: "unknown_provider" });
      return;
    }

    const parsedState = verifyUpstreamState(String(req.query.state));
    if (parsedState.mode !== "link") throw new Error("expected a link-mode upstream state");
    const { userId, provider, codeVerifier } = parsedState;
    if (provider !== req.params.providerId) throw new Error("upstream state does not match this provider");

    const tokens = await connector.exchangeCode({
      code: String(req.query.code),
      redirectUri: linkCallbackUrl(provider),
      codeVerifier,
    });
    const info = await connector.getUserInfo(tokens);

    const existingLink = await prisma.linkedIdentity.findUnique({
      where: { provider_providerUserId: { provider, providerUserId: info.id } },
    });
    if (existingLink && existingLink.userId !== userId) {
      res.status(409).type("html").send("<p>That account is already linked to a different NekoOAuth2Server account.</p>");
      return;
    }
    if (!existingLink) {
      await prisma.linkedIdentity.create({
        data: {
          userId,
          provider,
          providerUserId: info.id,
          providerUsername: info.username,
          verifiedVia: "oauth",
        },
      });
    }

    res.redirect("/account");
  } catch (err) {
    next(err);
  }
});

accountRouter.post("/linked-identities/:id/unlink", async (req, res) => {
  const userId = requireSession(req, res);
  if (!userId) return;

  await prisma.linkedIdentity.deleteMany({ where: { id: req.params.id, userId } });
  res.redirect("/account");
});

accountRouter.get("/link/vrchat", (req, res) => {
  const userId = requireSession(req, res);
  if (!userId) return;

  res.type("html").send(`
    <h1>Link VRChat</h1>
    <form method="post" action="/account/link/vrchat/bio">
      <input type="text" name="vrchatUserId" placeholder="Your VRChat user ID" required />
      <button type="submit">Verify via bio</button>
    </form>
    <form method="post" action="/account/link/vrchat/friend">
      <input type="text" name="vrchatUserId" placeholder="Your VRChat user ID" required />
      <button type="submit">Verify via friend request</button>
    </form>
  `);
});

accountRouter.post("/link/vrchat/bio", body, async (req, res, next) => {
  try {
    const userId = requireSession(req, res);
    if (!userId) return;

    const client = await getVRChatBotClient();
    if (!client) {
      res.status(503).json({ error: "vrchat_not_configured" });
      return;
    }

    const { vrchatUserId } = req.body as { vrchatUserId?: string };
    if (!vrchatUserId) {
      res.status(400).json({ error: "vrchatUserId required" });
      return;
    }

    const code = generateVerificationCode();

    // Fired in the background — verification can take up to 5 minutes of
    // polling, far longer than any HTTP request should stay open. The
    // resulting LinkedIdentity just shows up on /account once it completes.
    void verifyByBio(client, vrchatUserId, code).then(async (verified) => {
      if (!verified) return;
      const existing = await prisma.linkedIdentity.findUnique({
        where: { provider_providerUserId: { provider: "vrchat", providerUserId: vrchatUserId } },
      });
      if (existing) return;
      await prisma.linkedIdentity.create({
        data: { userId, provider: "vrchat", providerUserId: vrchatUserId, verifiedVia: "bio" },
      });
    });

    res.type("html").send(`<p>Paste this code into your VRChat bio, then check back at <a href="/account">your account</a> in a few minutes: <strong>${code}</strong></p>`);
  } catch (err) {
    next(err);
  }
});

accountRouter.post("/link/vrchat/friend", body, async (req, res, next) => {
  try {
    const userId = requireSession(req, res);
    if (!userId) return;

    const client = await getVRChatBotClient();
    if (!client) {
      res.status(503).json({ error: "vrchat_not_configured" });
      return;
    }

    const { vrchatUserId } = req.body as { vrchatUserId?: string };
    if (!vrchatUserId) {
      res.status(400).json({ error: "vrchatUserId required" });
      return;
    }

    void verifyByFriendRequest(client, vrchatUserId).then(async (verified) => {
      if (!verified) return;
      const existing = await prisma.linkedIdentity.findUnique({
        where: { provider_providerUserId: { provider: "vrchat", providerUserId: vrchatUserId } },
      });
      if (existing) return;
      await prisma.linkedIdentity.create({
        data: { userId, provider: "vrchat", providerUserId: vrchatUserId, verifiedVia: "friend_request" },
      });
    });

    res.type("html").send(`<p>Check your VRChat friend requests, then check back at <a href="/account">your account</a> in a few minutes.</p>`);
  } catch (err) {
    next(err);
  }
});

accountRouter.post("/delete", async (req, res) => {
  const userId = requireSession(req, res);
  if (!userId) return;

  await deleteUserAccount(userId);
  clearAccountSession(res);
  res.type("html").send("<p>Your account has been deleted.</p>");
});
