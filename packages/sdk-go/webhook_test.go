package neko

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

const testSecret = "test-webhook-secret"

func sign(body string, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyWebhookSignature_AcceptsCorrectlySignedBody(t *testing.T) {
	body := `{"event":"user.deleted","data":{"sub":"user-123"},"timestamp":"2026-01-01T00:00:00.000Z"}`
	if !VerifyWebhookSignature([]byte(body), sign(body, testSecret), testSecret) {
		t.Error("expected signature to verify")
	}
}

func TestVerifyWebhookSignature_RejectsTamperedBody(t *testing.T) {
	body := `{"event":"user.deleted","data":{"sub":"user-123"}}`
	signature := sign(body, testSecret)
	tampered := `{"event":"user.deleted","data":{"sub":"someone-else"}}`
	if VerifyWebhookSignature([]byte(tampered), signature, testSecret) {
		t.Error("expected tampered body to fail verification")
	}
}

func TestVerifyWebhookSignature_RejectsWrongSecret(t *testing.T) {
	body := `{"event":"user.deleted","data":{"sub":"user-123"}}`
	if VerifyWebhookSignature([]byte(body), sign(body, "wrong-secret"), testSecret) {
		t.Error("expected wrong-secret signature to fail")
	}
}

func TestVerifyWebhookSignature_RejectsMissingSignature(t *testing.T) {
	if VerifyWebhookSignature([]byte("{}"), "", testSecret) {
		t.Error("expected missing signature to fail")
	}
}

func TestVerifyWebhookSignature_RejectsMalformedSignature(t *testing.T) {
	if VerifyWebhookSignature([]byte("{}"), "not-a-real-signature", testSecret) {
		t.Error("expected malformed signature to fail")
	}
}

func TestParseWebhookPayload(t *testing.T) {
	body := `{"event":"user.deleted","data":{"sub":"user-123"},"timestamp":"2026-01-01T00:00:00.000Z"}`
	event, err := ParseWebhookPayload([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Event != "user.deleted" {
		t.Errorf("event = %q", event.Event)
	}
}

func TestVerifyAndParseWebhook_ReturnsEventWhenValid(t *testing.T) {
	body := `{"event":"user.deleted","data":{"sub":"user-123"},"timestamp":"2026-01-01T00:00:00.000Z"}`
	event, err := VerifyAndParseWebhook([]byte(body), sign(body, testSecret), testSecret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Event != "user.deleted" {
		t.Errorf("event = %q", event.Event)
	}
}

func TestVerifyAndParseWebhook_ErrorsWhenInvalid(t *testing.T) {
	body := `{"event":"user.deleted","data":{"sub":"user-123"}}`
	_, err := VerifyAndParseWebhook([]byte(body), "sha256=deadbeef", testSecret)
	if !errors.Is(err, ErrInvalidWebhookSignature) {
		t.Fatalf("expected ErrInvalidWebhookSignature, got %v", err)
	}
}
