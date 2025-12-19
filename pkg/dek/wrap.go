package dek

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/opentdf/spec/pkg/crypto"
)

// Wrap encrypts a DEK using the authority's RSA public key (RSA-OAEP with SHA-256).
// Returns the wrapped key as raw bytes.
//
// In the TDF spec, this wraps the DEK with the KAS public key.
// The term "authority" is used here to be agnostic - it could be a KAS,
// a smart contract, or any entity that controls key access.
func Wrap(dek []byte, authorityPublicKey *rsa.PublicKey) ([]byte, error) {
	if err := Validate(dek); err != nil {
		return nil, err
	}
	return crypto.WrapKeyRSA(dek, authorityPublicKey)
}

// WrapToBase64 encrypts a DEK and returns the result as a Base64 string.
// This is the format used in the manifest's keyAccess.wrappedKey field.
func WrapToBase64(dek []byte, authorityPublicKey *rsa.PublicKey) (string, error) {
	wrapped, err := Wrap(dek, authorityPublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(wrapped), nil
}

// Unwrap decrypts a wrapped DEK using the private key.
// The private key could belong to the authority (for rewrap operations)
// or the recipient (after rewrap).
func Unwrap(wrappedDEK []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	dek, err := crypto.UnwrapKeyRSA(wrappedDEK, privateKey)
	if err != nil {
		return nil, err
	}

	if err := Validate(dek); err != nil {
		return nil, fmt.Errorf("unwrapped key has invalid size: %w", err)
	}

	return dek, nil
}

// UnwrapFromBase64 decrypts a Base64-encoded wrapped DEK.
// This is the format stored in the manifest's keyAccess.wrappedKey field.
func UnwrapFromBase64(wrappedDEKBase64 string, privateKey *rsa.PrivateKey) ([]byte, error) {
	wrapped, err := base64.StdEncoding.DecodeString(wrappedDEKBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode wrapped key: %w", err)
	}
	return Unwrap(wrapped, privateKey)
}
