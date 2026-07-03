export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
}

export async function fetchDiscoveryDocument(issuer: string): Promise<DiscoveryDocument> {
  const base = issuer.replace(/\/$/, "");
  const res = await fetch(`${base}/.well-known/openid-configuration`);
  if (!res.ok) {
    throw new Error(`failed to fetch OIDC discovery document from ${issuer} (${res.status})`);
  }
  return (await res.json()) as DiscoveryDocument;
}
