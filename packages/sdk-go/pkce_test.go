package neko

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"testing"
)

var urlSafe = regexp.MustCompile(`^[A-Za-z0-9\-_]+$`)

func TestGenerateCodeVerifier_LengthWithinRFC7636(t *testing.T) {
	verifier, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Errorf("verifier length %d out of RFC 7636 range", len(verifier))
	}
	if !urlSafe.MatchString(verifier) {
		t.Errorf("verifier not url-safe: %q", verifier)
	}
}

func TestGenerateCodeChallenge_MatchesRFC7636S256(t *testing.T) {
	verifier := "test-verifier-value"
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := GenerateCodeChallenge(verifier); got != expected {
		t.Errorf("challenge = %q, want %q", got, expected)
	}
}

func TestGenerateCodeVerifier_DiffersEachCall(t *testing.T) {
	a, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	b, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == b {
		t.Error("expected two different verifiers")
	}
}

func TestGenerateState_NonEmptyAndURLSafe(t *testing.T) {
	state, err := GenerateState()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(state) == 0 {
		t.Error("expected non-empty state")
	}
	if !urlSafe.MatchString(state) {
		t.Errorf("state not url-safe: %q", state)
	}
}
