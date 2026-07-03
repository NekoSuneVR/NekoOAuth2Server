# NekoOAuth2Server Go SDK

`github.com/NekoSuneVR/NekoOAuth2Server/packages/sdk-go` — the Go counterpart to `@nekosunevr/oauth2-sdk` (TypeScript) and `nekosunevr-oauth2-sdk` (Python). Same shape, same feature set: PKCE, discovery, code exchange, `id_token` verification against the real JWKS (via [`lestrrat-go/jwx/v3`](https://github.com/lestrrat-go/jwx), the same "don't hand-roll crypto, use a proven library" choice made everywhere else in this project), and scope-gated userinfo.

## Install

```bash
go get github.com/NekoSuneVR/NekoOAuth2Server/packages/sdk-go
```

This is a Go module living in a subdirectory of a larger repository, not its own repo — Go supports this natively (see ["Publishing a module" in the Go modules reference](https://go.dev/ref/mod#vcs-version) for the general mechanism). There's no separate registry step the way npm/PyPI need: once a tag like `packages/sdk-go/v0.1.0` exists on this repo, `go get .../packages/sdk-go@v0.1.0` resolves it directly from GitHub, and the Go module proxy picks it up automatically.

## Usage

```go
package main

import (
	"context"
	"fmt"

	neko "github.com/NekoSuneVR/NekoOAuth2Server/packages/sdk-go"
)

func main() {
	ctx := context.Background()
	client := neko.NewClient(neko.Config{
		Issuer:      "http://localhost:4000/oidc",
		ClientID:    "your-client-id",
		RedirectURI: "http://localhost:8080/auth/callback",
	})

	authReq, err := client.CreateAuthorizationRequest(ctx, "")
	if err != nil {
		panic(err)
	}
	// store authReq.State and authReq.CodeVerifier, redirect to authReq.URL

	// ...once the callback arrives with ?code=...&state=...:
	tokens, err := client.ExchangeCode(ctx, code, codeVerifier)
	if err != nil {
		panic(err)
	}
	claims, err := client.VerifyIDToken(ctx, tokens.IDToken) // verified against the real JWKS
	if err != nil {
		panic(err)
	}
	sub, _ := claims.Subject()
	profile, err := client.GetUserInfo(ctx, tokens.AccessToken)
	fmt.Println(sub, profile)
}
```

No framework-specific helper is included (unlike the TS SDK's Express helper or the Python SDK's Flask helper) — Go's web frameworks (and net/http's own patterns) are varied enough that a "one true helper" doesn't fit the same way; wiring `CreateAuthorizationRequest`/`ExchangeCode`/`VerifyIDToken` into your own `net/http`, chi, gin, or echo handlers is a handful of lines and left to the caller.

## Webhooks

```go
event, err := neko.VerifyAndParseWebhook(rawBody, r.Header.Get("X-Neko-Signature"), webhookSecret)
if err != nil {
    // invalid signature
}
if event.Event == "user.deleted" {
    // purge your own cached copy
}
```

`rawBody` must be the exact bytes received — read the request body directly (`io.ReadAll(r.Body)`) before any JSON decoding, the signature is computed over the raw bytes.

## Development

```bash
go build ./...
go vet ./...
go test ./... -v
```
