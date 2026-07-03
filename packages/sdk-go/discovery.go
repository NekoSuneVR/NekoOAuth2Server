package neko

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type DiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func FetchDiscoveryDocument(issuer string) (*DiscoveryDocument, error) {
	base := strings.TrimRight(issuer, "/")
	res, err := http.Get(base + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch OIDC discovery document from %s (%d)", issuer, res.StatusCode)
	}
	var doc DiscoveryDocument
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}
