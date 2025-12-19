// Package dek provides Data Encryption Key (DEK) management for OpenTDF.
// This includes generation, wrapping, unwrapping, rewrapping, and key splitting.
package dek

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/opentdf/spec/pkg/crypto"
)

const (
	// DEKSize is the size of a DEK in bytes (256 bits for AES-256).
	DEKSize = 32
)

var (
	ErrInvalidDEKSize = errors.New("invalid DEK size: must be 32 bytes")
)

// Generate creates a new cryptographically secure Data Encryption Key.
// The DEK is a 256-bit (32 byte) random key suitable for AES-256-GCM.
func Generate() ([]byte, error) {
	dek := make([]byte, DEKSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}
	return dek, nil
}

// Validate checks if a DEK has the correct size.
func Validate(dek []byte) error {
	if len(dek) != DEKSize {
		return ErrInvalidDEKSize
	}
	return nil
}

// CalculatePolicyBinding computes the policy binding hash for a DEK.
// The binding is: Base64(HMAC-SHA256(DEK, Base64EncodedPolicy))
//
// This cryptographically links the policy to the DEK, preventing policy tampering.
// The authority (e.g., KAS in TDF spec) verifies this binding before releasing keys.
func CalculatePolicyBinding(dek []byte, policyBase64 string) (string, error) {
	if err := Validate(dek); err != nil {
		return "", err
	}
	return crypto.CalculatePolicyBinding(dek, policyBase64), nil
}

// VerifyPolicyBinding verifies that a policy binding hash is correct.
// Returns nil if valid, an error if the binding doesn't match.
func VerifyPolicyBinding(dek []byte, policyBase64, expectedHashBase64 string) error {
	if err := Validate(dek); err != nil {
		return err
	}
	return crypto.VerifyPolicyBinding(dek, policyBase64, expectedHashBase64)
}

