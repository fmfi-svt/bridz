package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const (
	statePurpose = "state"
	codePurpose  = "code"
)

// sealedState is carried to the upstream provider. It contains no access token.
type sealedState struct {
	ExpiresAt   int64  `json:"exp"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state,omitempty"`
	Nonce       string `json:"nonce"`
}

// sealedCode is the self-contained downstream authorization code.
type sealedCode struct {
	ExpiresAt   int64          `json:"exp"`
	ClientID    string         `json:"client_id"`
	RedirectURI string         `json:"redirect_uri"`
	Nonce       string         `json:"nonce,omitempty"`
	Subject     string         `json:"sub"`
	Claims      map[string]any `json:"claims"`
}

func (b *broker) sealState(state sealedState) (string, error) {
	return b.seal(statePurpose, state)
}

func (b *broker) sealCode(code sealedCode) (string, error) {
	return b.seal(codePurpose, code)
}

// seal encrypts an authenticated JSON payload as nonce || ciphertext.
// purpose is AEAD additional authenticated data, separating state from code.
func (b *broker) seal(purpose string, value any) (string, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(b.stateKey)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := append(nonce, aead.Seal(nil, nonce, plain, []byte(purpose))...)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (b *broker) openState(raw string) (sealedState, error) {
	var state sealedState
	err := b.open(raw, statePurpose, &state)
	if err != nil || state.ExpiresAt < time.Now().Unix() {
		return sealedState{}, errors.New("invalid state")
	}
	return state, nil
}

func (b *broker) openCode(raw string) (sealedCode, error) {
	var code sealedCode
	err := b.open(raw, codePurpose, &code)
	if err != nil || code.ExpiresAt < time.Now().Unix() {
		return sealedCode{}, errors.New("invalid code")
	}
	return code, nil
}

func (b *broker) open(raw, purpose string, value any) error {
	sealed, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(b.stateKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(sealed) < aead.NonceSize() {
		return errors.New("invalid sealed value")
	}
	plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte(purpose))
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, value)
}

func randomString(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
