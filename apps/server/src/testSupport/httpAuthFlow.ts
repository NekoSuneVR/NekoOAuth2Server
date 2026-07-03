import crypto from "node:crypto";
import type request from "supertest";

export function pkcePair() {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

// oidc-provider's internal redirects (e.g. the post-interaction "resume" hop)
// are host-qualified using the *incoming request's* host, not our static
// issuer config — which is a real, correct koa/oidc-provider behavior, but it
// means they don't match supertest's own ephemeral per-test host. Only the
// path+query is ever meaningful for driving the flow against the same agent.
function toRequestPath(location: string) {
  if (location.startsWith("http://") || location.startsWith("https://")) {
    const url = new URL(location);
    return `${url.pathname}${url.search}`;
  }
  return location;
}

/**
 * Drives the real HTTP authorize -> login -> consent -> redirect flow
 * (through our own interaction routes, not internal model shortcuts), and
 * returns the issued authorization code + state.
 */
export async function runAuthorizationRequest(
  agent: ReturnType<typeof request.agent>,
  query: Record<string, string>,
  credentials: { email: string; password: string },
  redirectUri: string,
) {
  let res = await agent.get("/oidc/auth").query(query);
  let location = res.headers.location as string | undefined;

  for (let hops = 0; hops < 10 && location && !location.startsWith(redirectUri); hops += 1) {
    const path = toRequestPath(location);
    if (path.includes("/interaction/")) {
      const page = await agent.get(path);
      const uid = path.split("/interaction/")[1]?.split("/")[0];
      if (page.text.includes("Sign in")) {
        res = await agent
          .post(`/oidc/interaction/${uid}/login`)
          .type("form")
          .send({ email: credentials.email, password: credentials.password });
      } else {
        res = await agent.post(`/oidc/interaction/${uid}/confirm`).type("form").send({});
      }
    } else {
      res = await agent.get(path);
    }
    location = res.headers.location as string | undefined;
  }

  if (!location || !location.startsWith(redirectUri)) {
    throw new Error(`authorization flow did not reach ${redirectUri}, stuck at ${location}`);
  }

  const redirectUrl = new URL(location);
  const error = redirectUrl.searchParams.get("error");
  if (error) {
    throw new Error(`authorization failed: ${error} - ${redirectUrl.searchParams.get("error_description")}`);
  }
  return {
    code: redirectUrl.searchParams.get("code")!,
    state: redirectUrl.searchParams.get("state"),
  };
}
