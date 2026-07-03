// Human-readable descriptions for the consent screen (interactions.ts) — a
// downstream app requesting a scope should show the user plain language, not
// raw OAuth scope identifiers. Falls back to the raw name for anything not
// listed here (a new resource-indicator scope, say) rather than hiding it.
export const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: "Confirm it's you (your unique account ID)",
  profile: "Your name and profile picture",
  email: "Your email address",
  offline_access: "Stay signed in on your behalf, even when you're not active",
  roles: "Your roles and permissions for this app",
  "internal:read": "Read access to internal API data",
  "internal:write": "Write access to internal API data",
};

export function describeScope(scope: string): string {
  return SCOPE_DESCRIPTIONS[scope] ?? `Access to "${scope}"`;
}
