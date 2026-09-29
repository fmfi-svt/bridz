package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type nonceContextKey struct{}
type stateCookieContextKey struct{}

type broker struct {
	op.UnimplementedServer

	cfg        config
	clients    map[string]clientConfig
	stateAEAD  cipher.AEAD
	signingKey *rsa.PrivateKey
	upstream   rp.RelyingParty
}

func newBroker(cfg config) (*broker, error) {
	stateKey, err := base64.URLEncoding.DecodeString(cfg.Keys.StateEncryptionKey)
	if err != nil {
		stateKey, err = base64.RawURLEncoding.DecodeString(cfg.Keys.StateEncryptionKey)
	}
	if err != nil || len(stateKey) != 32 {
		return nil, errors.New("keys.state_encryption_key must be a base64url-encoded 32-byte key")
	}

	block, err := aes.NewCipher(stateKey)
	if err != nil {
		return nil, fmt.Errorf("state encryption key: %w", err)
	}
	stateAEAD, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("state encryption key: %w", err)
	}

	key, err := parseRSAKey([]byte(cfg.Keys.SigningKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}

	clients, err := validateClients(cfg.Clients)
	if err != nil {
		return nil, err
	}

	b := &broker{cfg: cfg, clients: clients, stateAEAD: stateAEAD, signingKey: key}

	upstream, err := rp.NewRelyingPartyOIDC(
		context.Background(),
		cfg.Upstream.Issuer,
		cfg.Upstream.ClientID,
		cfg.Upstream.ClientSecret,
		cfg.Upstream.RedirectURI,
		cfg.Upstream.Scopes,
		rp.WithVerifierOpts(
			rp.WithNonce(func(ctx context.Context) string {
				nonce, _ := ctx.Value(nonceContextKey{}).(string)
				return nonce
			}),
			rp.WithSupportedSigningAlgorithms("RS256"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("upstream discovery: %w", err)
	}
	b.upstream = upstream
	return b, nil
}
