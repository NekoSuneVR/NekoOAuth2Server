package neko

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// WebhookEvent mirrors the server's payload shape exactly:
// { "event": "...", "data": {...}, "timestamp": "..." }.
type WebhookEvent struct {
	Event     string          `json:"event"`
	Data      json.RawMessage `json:"data"`
	Timestamp string          `json:"timestamp"`
}

var ErrInvalidWebhookSignature = errors.New("invalid webhook signature")

// VerifyWebhookSignature matches the server's own signing scheme exactly:
// `X-Neko-Signature: sha256=<hex hmac-sha256 of the raw request body>`.
// rawBody must be the exact bytes the server sent -- re-serializing JSON
// after parsing can differ enough (key order, whitespace) to fail
// verification even for "the same" content.
func VerifyWebhookSignature(rawBody []byte, signatureHeader string, secret string) bool {
	if signatureHeader == "" {
		return false
	}
	parts := strings.SplitN(signatureHeader, "=", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(rawBody)
	expected := mac.Sum(nil)

	provided, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	return hmac.Equal(expected, provided)
}

func ParseWebhookPayload(rawBody []byte) (*WebhookEvent, error) {
	var event WebhookEvent
	if err := json.Unmarshal(rawBody, &event); err != nil {
		return nil, err
	}
	return &event, nil
}

func VerifyAndParseWebhook(rawBody []byte, signatureHeader string, secret string) (*WebhookEvent, error) {
	if !VerifyWebhookSignature(rawBody, signatureHeader, secret) {
		return nil, ErrInvalidWebhookSignature
	}
	return ParseWebhookPayload(rawBody)
}
