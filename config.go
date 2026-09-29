package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"gopkg.in/yaml.v3"
)

const (
	authorizationCodeLifetime = 15 * time.Second
	accessTokenLifetime       = 15 * time.Minute
	idTokenLifetime           = 15 * time.Minute
)

type config struct {
	Issuer string `yaml:"issuer"`
	Listen string `yaml:"listen"`

	Keys struct {
		StateEncryptionKey string `yaml:"state_encryption_key"`
		SigningKeyPEM      string `yaml:"signing_key_pem"`
		SigningKeyID       string `yaml:"signing_key_id"`
	} `yaml:"keys"`

	Upstream struct {
		Issuer       string   `yaml:"issuer"`
		ClientID     string   `yaml:"client_id"`
		ClientSecret string   `yaml:"client_secret"`
		Scopes       []string `yaml:"scopes"`
		RedirectURI  string   `yaml:"redirect_uri"`
	} `yaml:"upstream"`

	Clients []clientConfig `yaml:"clients"`
}

type clientConfig struct {
	ID           string   `yaml:"id"`
	Secret       string   `yaml:"secret"`
	RedirectURIs []string `yaml:"redirect_uris"`
}

func readConfig(path string) (config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return config{}, err
	}

	var cfg config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return config{}, err
	}
	if cfg.Issuer == "" || cfg.Listen == "" || cfg.Upstream.Issuer == "" || cfg.Upstream.RedirectURI == "" {
		return config{}, errors.New("issuer, listen, upstream.issuer, and upstream.redirect_uri are required")
	}
	return cfg, nil
}

func parseRSAKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not RSA")
	}
	return rsaKey, nil
}

// configuredClient adapts YAML client data to ZITADEL's OP route validator.
type configuredClient struct{ clientConfig }

func (c configuredClient) GetID() string                       { return c.ID }
func (c configuredClient) RedirectURIs() []string              { return c.clientConfig.RedirectURIs }
func (c configuredClient) PostLogoutRedirectURIs() []string    { return nil }
func (c configuredClient) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (c configuredClient) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodBasic }
func (c configuredClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c configuredClient) GrantTypes() []oidc.GrantType { return []oidc.GrantType{oidc.GrantTypeCode} }
func (c configuredClient) LoginURL(string) string       { return "" }
func (c configuredClient) AccessTokenType() op.AccessTokenType {
	return op.AccessTokenTypeJWT
}
func (c configuredClient) IDTokenLifetime() time.Duration { return idTokenLifetime }
func (c configuredClient) DevMode() bool                  { return false }
func (c configuredClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return nil
}

func (c configuredClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return nil
}
func (c configuredClient) IsScopeAllowed(string) bool           { return true }
func (c configuredClient) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c configuredClient) ClockSkew() time.Duration             { return 0 }

var _ op.Client = configuredClient{}

func validateClients(clients []clientConfig) (map[string]clientConfig, error) {
	result := make(map[string]clientConfig, len(clients))
	for _, client := range clients {
		if client.ID == "" || client.Secret == "" || len(client.RedirectURIs) == 0 {
			return nil, errors.New("every client needs id, secret, and redirect_uris")
		}
		if _, exists := result[client.ID]; exists {
			return nil, fmt.Errorf("duplicate client %q", client.ID)
		}
		result[client.ID] = client
	}
	return result, nil
}
