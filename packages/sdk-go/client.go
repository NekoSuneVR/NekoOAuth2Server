// Package neko is a thin OIDC relying-party client for NekoOAuth2Server.
// Same shape as the TypeScript SDK (@nekosunevr/oauth2-sdk) and the Python
// SDK (nekosunevr-oauth2-sdk) -- a straight port, not a different design.
package neko

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string // only for confidential clients
	RedirectURI  string
	// Scope defaults to "openid profile email" when empty.
	Scope string
}

type Client struct {
	config     Config
	httpClient *http.Client

	discovery *DiscoveryDocument
	jwks      jwk.Set
}

func NewClient(config Config) *Client {
	if config.Scope == "" {
		config.Scope = "openid profile email"
	}
	return &Client{config: config, httpClient: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) ensureDiscovery(ctx context.Context) (*DiscoveryDocument, error) {
	if c.discovery == nil {
		doc, err := FetchDiscoveryDocument(c.config.Issuer)
		if err != nil {
			return nil, err
		}
		set, err := jwk.Fetch(ctx, doc.JWKSURI)
		if err != nil {
			return nil, err
		}
		c.discovery = doc
		c.jwks = set
	}
	return c.discovery, nil
}

type AuthorizationRequest struct {
	URL          string
	State        string
	CodeVerifier string
}

// CreateAuthorizationRequest builds the authorize redirect URL and the
// PKCE/state values the caller must persist until the callback. Pass an
// empty scope to use the client's configured default.
func (c *Client) CreateAuthorizationRequest(ctx context.Context, scope string) (*AuthorizationRequest, error) {
	discovery, err := c.ensureDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		return nil, err
	}
	challenge := GenerateCodeChallenge(verifier)
	state, err := GenerateState()
	if err != nil {
		return nil, err
	}
	if scope == "" {
		scope = c.config.Scope
	}

	q := url.Values{}
	q.Set("client_id", c.config.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", c.config.RedirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	return &AuthorizationRequest{
		URL:          discovery.AuthorizationEndpoint + "?" + q.Encode(),
		State:        state,
		CodeVerifier: verifier,
	}, nil
}

type TokenSet struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope,omitempty"`
}

type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (c *Client) tokenHeaders() http.Header {
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	if c.config.ClientSecret != "" {
		basic := base64.StdEncoding.EncodeToString([]byte(c.config.ClientID + ":" + c.config.ClientSecret))
		headers.Set("Authorization", "Basic "+basic)
	}
	return headers
}

func (c *Client) tokenRequest(ctx context.Context, endpoint string, form url.Values) (*TokenSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = c.tokenHeaders()

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		var errBody tokenErrorResponse
		_ = json.Unmarshal(body, &errBody)
		return nil, fmt.Errorf("token request failed: %s %s", errBody.Error, errBody.ErrorDescription)
	}

	var tokens TokenSet
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}
	return &tokens, nil
}

func (c *Client) ExchangeCode(ctx context.Context, code, codeVerifier string) (*TokenSet, error) {
	discovery, err := c.ensureDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.config.RedirectURI)
	form.Set("client_id", c.config.ClientID)
	form.Set("code_verifier", codeVerifier)
	return c.tokenRequest(ctx, discovery.TokenEndpoint, form)
}

func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error) {
	discovery, err := c.ensureDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.config.ClientID)
	return c.tokenRequest(ctx, discovery.TokenEndpoint, form)
}

// VerifyIDToken verifies signature, issuer, and audience against the
// server's real JWKS -- never trust an unverified id_token. Returns the
// parsed jwt.Token; use .Subject() for `sub`, or .Get("claim", &dest) for
// anything else.
func (c *Client) VerifyIDToken(ctx context.Context, idToken string) (jwt.Token, error) {
	discovery, err := c.ensureDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	return jwt.Parse(
		[]byte(idToken),
		jwt.WithKeySet(c.jwks),
		jwt.WithIssuer(discovery.Issuer),
		jwt.WithAudience(c.config.ClientID),
	)
}

func (c *Client) GetUserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	discovery, err := c.ensureDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed (%d)", res.StatusCode)
	}

	var profile map[string]any
	if err := json.NewDecoder(res.Body).Decode(&profile); err != nil {
		return nil, err
	}
	return profile, nil
}
