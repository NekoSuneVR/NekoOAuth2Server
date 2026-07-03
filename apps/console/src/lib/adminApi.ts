import { auth } from "@/auth";

const SERVER_URL = process.env.NEKO_SERVER_URL ?? "http://localhost:4000";

export class AdminApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Every admin screen calls the real server's /api/admin/* endpoints
 * server-side (Server Components / Server Actions), never from the
 * browser — the access token lives only in the NextAuth JWT session
 * cookie, never sent to client-side JS. This is the one place that
 * attaches it.
 */
export async function callAdminApi<T>(path: string, init: RequestInit = {}): Promise<T> {
  const session = await auth();
  if (!session?.accessToken) {
    throw new AdminApiError(401, "not signed in");
  }

  const res = await fetch(`${SERVER_URL}${path}`, {
    ...init,
    headers: {
      ...init.headers,
      Authorization: `Bearer ${session.accessToken}`,
      ...(init.body ? { "Content-Type": "application/json" } : {}),
    },
    cache: "no-store",
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new AdminApiError(res.status, body.error_description ?? body.error ?? `request failed (${res.status})`);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}
