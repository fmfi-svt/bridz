package main

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const stateCookieName = "__Host-bridz-state"

func (b *broker) bindStateCookie(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		binding, err := randomString(32)
		if err != nil {
			http.Error(w, "could not start authorization", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{Name: stateCookieName, Value: binding, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), stateCookieContextKey{}, binding)))
	})
}

func (b *broker) upstreamCallback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("error") != "" {
		http.Error(w, "upstream authorization failed", http.StatusBadRequest)
		return
	}

	state, err := b.openState(r.URL.Query().Get("state"))
	if err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie(stateCookieName)
	if err != nil || cookie.Value != state.CookieBinding {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookie.Name, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})

	if r.URL.Query().Get("code") == "" {
		http.Error(w, "missing upstream code", http.StatusBadRequest)
		return
	}

	ctx := context.WithValue(r.Context(), nonceContextKey{}, state.Nonce)
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, r.URL.Query().Get("code"), b.upstream)
	if err != nil {
		http.Error(w, "upstream token exchange failed", http.StatusBadGateway)
		return
	}

	info, err := rp.Userinfo[*oidc.UserInfo](ctx, tokens.AccessToken, tokens.Type(), tokens.IDTokenClaims.GetSubject(), b.upstream)
	if err != nil {
		http.Error(w, "upstream userinfo failed", http.StatusBadGateway)
		return
	}

	claims := nonProtocolClaims(claimMap(tokens.IDTokenClaims))
	maps.Copy(claims, nonProtocolClaims(claimMap(info)))

	code, err := b.sealCode(sealedCode{
		ExpiresAt:   time.Now().Add(authorizationCodeLifetime).Unix(),
		ClientID:    state.ClientID,
		RedirectURI: state.RedirectURI,
		Nonce:       state.Nonce,
		Subject:     tokens.IDTokenClaims.GetSubject(),
		Claims:      claims,
	})
	if err != nil {
		http.Error(w, "could not create authorization code", http.StatusInternalServerError)
		return
	}

	redirect, _ := url.Parse(state.RedirectURI)
	query := redirect.Query()
	query.Set("code", code)
	if state.State != "" {
		query.Set("state", state.State)
	}
	redirect.RawQuery = query.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (b *broker) signToken(code sealedCode, lifetime time.Duration, idToken bool) (string, error) {
	now := time.Now().UTC()
	claims := make(map[string]any, len(code.Claims)+7)

	maps.Copy(claims, code.Claims)
	claims["iss"] = b.cfg.Issuer
	claims["sub"] = code.Subject
	claims["aud"] = code.ClientID
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(lifetime).Unix()
	if idToken {
		claims["nonce"] = code.Nonce
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: b.signingKey}, (&jose.SignerOptions{}).WithHeader("kid", b.cfg.Keys.SigningKeyID).WithType("JWT"))
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

func (b *broker) verifyAccessToken(raw string) (map[string]any, error) {
	if raw == "" {
		return nil, errors.New("missing bearer token")
	}

	token, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	if err := token.Claims(&b.signingKey.PublicKey, &claims); err != nil {
		return nil, err
	}

	if claims["iss"] != b.cfg.Issuer || expired(claims) {
		return nil, errors.New("expired or foreign token")
	}

	return claims, nil
}

func claimMap(value any) map[string]any {
	data, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var claims map[string]any
	if json.Unmarshal(data, &claims) != nil {
		return nil
	}
	return claims
}

func nonProtocolClaims(input map[string]any) map[string]any {
	claims := make(map[string]any, len(input))
	for key, value := range input {
		switch key {
		case "iss", "sub", "aud", "exp", "iat", "nbf", "nonce", "at_hash", "c_hash", "azp":
			continue
		}
		claims[key] = value
	}
	return claims
}

func bearerToken(header string) string {
	parts := strings.Fields(header)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return parts[1]
	}
	return ""
}

func expired(claims map[string]any) bool {
	exp, ok := claims["exp"].(float64)
	return !ok || time.Now().Unix() >= int64(exp)
}
