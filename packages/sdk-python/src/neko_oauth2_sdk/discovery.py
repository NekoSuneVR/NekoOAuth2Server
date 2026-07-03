from dataclasses import dataclass

import requests


@dataclass
class DiscoveryDocument:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str


def fetch_discovery_document(issuer: str) -> DiscoveryDocument:
    base = issuer.rstrip("/")
    res = requests.get(f"{base}/.well-known/openid-configuration", timeout=10)
    res.raise_for_status()
    data = res.json()
    return DiscoveryDocument(
        issuer=data["issuer"],
        authorization_endpoint=data["authorization_endpoint"],
        token_endpoint=data["token_endpoint"],
        userinfo_endpoint=data["userinfo_endpoint"],
        jwks_uri=data["jwks_uri"],
    )
