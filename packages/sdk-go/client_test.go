package neko

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	testClientID    = "test-client"
	testRedirectURI = "http://localhost:3000/callback"
	testKID         = "test-key-1"
)

// mockOidcServer stands in for NekoOAuth2Server itself -- the same "mock
// external services with a real local server" pattern used throughout this
// project's own test suites, not a mock of the HTTP client.
type mockOidcServer struct {
	server       *httptest.Server
	privateKey   *rsa.PrivateKey
	signingKey   jwk.Key
	mu           sync.Mutex
	issuedCodes  map[string]issuedCode
	refreshToken string
}

type issuedCode struct {
	codeChallenge string
	sub           string
}

func newMockOidcServer(t *testing.T) *mockOidcServer {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signingKey, err := jwk.Import(privateKey)
	if err != nil {
		t.Fatalf("import key: %v", err)
	}
	if err := signingKey.Set("kid", testKID); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := signingKey.Set("alg", jwa.RS256().String()); err != nil {
		t.Fatalf("set alg: %v", err)
	}

	m := &mockOidcServer{privateKey: privateKey, signingKey: signingKey, issuedCodes: map[string]issuedCode{}}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockOidcServer) baseURL() string { return m.server.URL }

func (m *mockOidcServer) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/.well-known/openid-configuration":
		writeJSON(w, http.StatusOK, map[string]string{
			"issuer":                 m.baseURL(),
			"authorization_endpoint": m.baseURL() + "/authorize",
			"token_endpoint":         m.baseURL() + "/token",
			"userinfo_endpoint":      m.baseURL() + "/userinfo",
			"jwks_uri":               m.baseURL() + "/jwks",
		})
	case r.URL.Path == "/jwks":
		publicKey, err := jwk.PublicKeyOf(m.signingKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		set := jwk.NewSet()
		_ = set.AddKey(publicKey)
		buf, _ := json.Marshal(set)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(buf)
	case r.URL.Path == "/userinfo":
		if r.Header.Get("Authorization") == "Bearer access-for-test-user" {
			writeJSON(w, http.StatusOK, map[string]string{"sub": "test-user", "name": "Test User", "email": "test-user@example.com"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	case r.URL.Path == "/token" && r.Method == http.MethodPost:
		m.handleToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (m *mockOidcServer) handleToken(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))

	switch form.Get("grant_type") {
	case "authorization_code":
		m.mu.Lock()
		issued, ok := m.issuedCodes[form.Get("code")]
		m.mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "unknown code"})
			return
		}
		sum := sha256.Sum256([]byte(form.Get("code_verifier")))
		computed := base64.RawURLEncoding.EncodeToString(sum[:])
		if computed != issued.codeChallenge {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
		m.mu.Lock()
		delete(m.issuedCodes, form.Get("code"))
		m.refreshToken = randomHex(16)
		refreshToken := m.refreshToken
		m.mu.Unlock()

		idToken, err := m.signIDToken(issued.sub)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  "access-for-" + issued.sub,
			"id_token":      idToken,
			"refresh_token": refreshToken,
			"expires_in":    3600,
			"token_type":    "Bearer",
			"scope":         "openid profile email",
		})
	case "refresh_token":
		m.mu.Lock()
		valid := form.Get("refresh_token") == m.refreshToken
		m.mu.Unlock()
		if !valid {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "refreshed-access-token", "expires_in": 3600, "token_type": "Bearer"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (m *mockOidcServer) signIDToken(sub string) (string, error) {
	token, err := jwt.NewBuilder().Subject(sub).Issuer(m.baseURL()).Audience([]string{testClientID}).Build()
	if err != nil {
		return "", err
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), m.signingKey))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

func (m *mockOidcServer) issueCode(codeVerifier, sub string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	code := randomHex(8)
	m.mu.Lock()
	m.issuedCodes[code] = issuedCode{codeChallenge: challenge, sub: sub}
	m.mu.Unlock()
	return code
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func randomHex(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("%x", buf)
}

func newTestClient(m *mockOidcServer) *Client {
	return NewClient(Config{Issuer: m.baseURL(), ClientID: testClientID, RedirectURI: testRedirectURI})
}

func TestCreateAuthorizationRequest_HasMandatoryPKCEAndFreshState(t *testing.T) {
	m := newMockOidcServer(t)
	client := newTestClient(m)

	first, err := client.CreateAuthorizationRequest(context.Background(), "")
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	second, err := client.CreateAuthorizationRequest(context.Background(), "")
	if err != nil {
		t.Fatalf("second request: %v", err)
	}

	parsed, err := url.Parse(first.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != m.baseURL()+"/authorize" {
		t.Errorf("unexpected authorize base: %s", got)
	}
	q := parsed.Query()
	if q.Get("client_id") != testClientID {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") == "" {
		t.Error("code_challenge missing")
	}
	if first.State == second.State {
		t.Error("state should differ between requests")
	}
	if first.CodeVerifier == second.CodeVerifier {
		t.Error("code_verifier should differ between requests")
	}
}

func TestExchangeCode_VerifiesIDTokenAndFetchesUserInfo(t *testing.T) {
	m := newMockOidcServer(t)
	client := newTestClient(m)
	ctx := context.Background()

	req, err := client.CreateAuthorizationRequest(ctx, "")
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	code := m.issueCode(req.CodeVerifier, "test-user")

	tokens, err := client.ExchangeCode(ctx, code, req.CodeVerifier)
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}
	if tokens.AccessToken != "access-for-test-user" {
		t.Errorf("access_token = %q", tokens.AccessToken)
	}
	if tokens.IDToken == "" {
		t.Fatal("id_token missing")
	}

	claims, err := client.VerifyIDToken(ctx, tokens.IDToken)
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	sub, _ := claims.Subject()
	if sub != "test-user" {
		t.Errorf("sub = %q", sub)
	}

	profile, err := client.GetUserInfo(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("userinfo: %v", err)
	}
	if profile["email"] != "test-user@example.com" {
		t.Errorf("email = %v", profile["email"])
	}
}

func TestExchangeCode_RejectsWrongCodeVerifier(t *testing.T) {
	m := newMockOidcServer(t)
	client := newTestClient(m)
	ctx := context.Background()

	req, err := client.CreateAuthorizationRequest(ctx, "")
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	code := m.issueCode(req.CodeVerifier, "test-user")

	_, err = client.ExchangeCode(ctx, code, "a-totally-different-verifier-value")
	if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("expected invalid_grant error, got %v", err)
	}
}

func TestVerifyIDToken_RejectsForgedTokenFromUnrelatedKey(t *testing.T) {
	m := newMockOidcServer(t)
	client := newTestClient(m)
	ctx := context.Background()
	if _, err := client.CreateAuthorizationRequest(ctx, ""); err != nil {
		t.Fatalf("populate discovery: %v", err)
	}

	unrelatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate unrelated key: %v", err)
	}
	unrelatedJWK, err := jwk.Import(unrelatedKey)
	if err != nil {
		t.Fatalf("import unrelated key: %v", err)
	}
	_ = unrelatedJWK.Set("kid", testKID)
	_ = unrelatedJWK.Set("alg", jwa.RS256().String())

	token, err := jwt.NewBuilder().Subject("attacker").Issuer(m.baseURL()).Audience([]string{testClientID}).Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	forged, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), unrelatedJWK))
	if err != nil {
		t.Fatalf("sign forged token: %v", err)
	}

	if _, err := client.VerifyIDToken(ctx, string(forged)); err == nil {
		t.Fatal("expected forged token to be rejected")
	}
}

func TestVerifyIDToken_RejectsWrongAudience(t *testing.T) {
	m := newMockOidcServer(t)
	client := newTestClient(m)
	ctx := context.Background()
	if _, err := client.CreateAuthorizationRequest(ctx, ""); err != nil {
		t.Fatalf("populate discovery: %v", err)
	}

	token, err := jwt.NewBuilder().Subject("test-user").Issuer(m.baseURL()).Audience([]string{"some-other-client"}).Build()
	if err != nil {
		t.Fatalf("build token: %v", err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), m.signingKey))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	if _, err := client.VerifyIDToken(ctx, string(signed)); err == nil {
		t.Fatal("expected wrong-audience token to be rejected")
	}
}

func TestRefreshToken(t *testing.T) {
	m := newMockOidcServer(t)
	client := newTestClient(m)
	ctx := context.Background()

	req, err := client.CreateAuthorizationRequest(ctx, "")
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	code := m.issueCode(req.CodeVerifier, "test-user")
	tokens, err := client.ExchangeCode(ctx, code, req.CodeVerifier)
	if err != nil {
		t.Fatalf("exchange code: %v", err)
	}

	refreshed, err := client.RefreshToken(ctx, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("refresh token: %v", err)
	}
	if refreshed.AccessToken != "refreshed-access-token" {
		t.Errorf("access_token = %q", refreshed.AccessToken)
	}
}
