package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"slices"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/oauth2"
)

func (b *broker) Discovery(_ context.Context, _ *op.Request[struct{}]) (*op.Response, error) {
	return op.NewResponse(map[string]any{
		"issuer":                                b.cfg.Issuer,
		"authorization_endpoint":                b.cfg.Issuer + "/authorize",
		"token_endpoint":                        b.cfg.Issuer + "/token",
		"userinfo_endpoint":                     b.cfg.Issuer + "/userinfo",
		"jwks_uri":                              b.cfg.Issuer + "/keys",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	}), nil
}

func (b *broker) Keys(_ context.Context, _ *op.Request[struct{}]) (*op.Response, error) {
	return op.NewResponse(map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"kid": b.cfg.Keys.SigningKeyID,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(b.signingKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(bigEndian(b.signingKey.E)),
	}}}), nil
}

func (b *broker) VerifyAuthRequest(_ context.Context, r *op.Request[oidc.AuthRequest]) (*op.ClientRequest[oidc.AuthRequest], error) {
	request := r.Data
	client, ok := b.clients[request.ClientID]
	if !ok || request.ResponseType != oidc.ResponseTypeCode || !slices.Contains(client.RedirectURIs, request.RedirectURI) {
		return nil, oidc.ErrInvalidRequest()
	}

	return &op.ClientRequest[oidc.AuthRequest]{Request: r, Client: configuredClient{client}}, nil
}

func (b *broker) Authorize(_ context.Context, r *op.ClientRequest[oidc.AuthRequest]) (*op.Redirect, error) {
	nonce, err := randomString(32)
	if err != nil {
		return nil, err
	}

	state, err := b.sealState(sealedState{
		ExpiresAt:   time.Now().Add(authorizationCodeLifetime).Unix(),
		ClientID:    r.Data.ClientID,
		RedirectURI: r.Data.RedirectURI,
		State:       r.Data.State,
		Nonce:       nonce,
	})
	if err != nil {
		return nil, err
	}

	return op.NewRedirect(rp.AuthURL(state, b.upstream, rp.AuthURLOpt(func() []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", nonce)}
	}))), nil
}

// VerifyClient accepts only configured confidential clients.
func (b *broker) VerifyClient(_ context.Context, r *op.Request[op.ClientCredentials]) (op.Client, error) {
	client, ok := b.clients[r.Data.ClientID]
	if !ok || subtle.ConstantTimeCompare([]byte(client.Secret), []byte(r.Data.ClientSecret)) != 1 {
		return nil, oidc.ErrInvalidClient()
	}

	return configuredClient{client}, nil
}

func (b *broker) CodeExchange(_ context.Context, r *op.ClientRequest[oidc.AccessTokenRequest]) (*op.Response, error) {
	code, err := b.openCode(r.Data.Code)
	if err != nil {
		return nil, oidc.ErrInvalidGrant()
	}
	if code.ClientID != r.Client.GetID() || code.RedirectURI != r.Data.RedirectURI {
		return nil, oidc.ErrInvalidGrant()
	}

	access, err := b.signToken(code, accessTokenLifetime, false)
	if err != nil {
		return nil, err
	}
	idToken, err := b.signToken(code, idTokenLifetime, true)
	if err != nil {
		return nil, err
	}

	return op.NewResponse(oidc.AccessTokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   uint64(accessTokenLifetime.Seconds()),
		IDToken:     idToken,
	}), nil
}

func (b *broker) UserInfo(_ context.Context, r *op.Request[oidc.UserInfoRequest]) (*op.Response, error) {
	claims, err := b.verifyAccessToken(bearerToken(r.Header.Get("Authorization")))
	if err != nil {
		return nil, oidc.ErrInvalidRequest()
	}

	response := nonProtocolClaims(claims)
	response["sub"] = claims["sub"]
	return op.NewResponse(response), nil
}

func bigEndian(value int) []byte {
	if value == 0 {
		return []byte{0}
	}
	var bytes [8]byte
	index := len(bytes)
	for value > 0 {
		index--
		bytes[index] = byte(value)
		value >>= 8
	}
	return bytes[index:]
}
