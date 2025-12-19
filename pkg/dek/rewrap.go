package dek

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/opentdf/spec/pkg/crypto"
)

// Rewrap decrypts a wrapped DEK using the authority's private key,
// then re-encrypts it with the recipient's public key.
//
// This is the core operation performed by a key access authority (e.g., KAS)
// when a client requests access to encrypted data. The flow is:
// 1. Client sends the wrapped DEK to the authority
// 2. Authority verifies the client is authorized (via policy check)
// 3. Authority unwraps the DEK with its private key
// 4. Authority rewraps the DEK with the client's public key
// 5. Client unwraps the DEK with their private key
//
// This ensures the authority never exposes the plaintext DEK over the network.
func Rewrap(wrappedDEK []byte, authorityPrivateKey *rsa.PrivateKey, recipientPublicKey *rsa.PublicKey) ([]byte, error) {
	rewrapped, err := crypto.RewrapKeyRSA(wrappedDEK, authorityPrivateKey, recipientPublicKey)
	if err != nil {
		return nil, err
	}
	return rewrapped, nil
}

// RewrapFromBase64 performs a rewrap operation on a Base64-encoded wrapped DEK.
// Returns the rewrapped key as a Base64 string.
func RewrapFromBase64(wrappedDEKBase64 string, authorityPrivateKey *rsa.PrivateKey, recipientPublicKey *rsa.PublicKey) (string, error) {
	wrapped, err := base64.StdEncoding.DecodeString(wrappedDEKBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode wrapped key: %w", err)
	}

	rewrapped, err := Rewrap(wrapped, authorityPrivateKey, recipientPublicKey)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(rewrapped), nil
}

// RewrapWithPolicyVerification performs a rewrap after verifying the policy binding.
// This is the full authority-side operation that ensures the policy hasn't been tampered with.
//
// Parameters:
//   - wrappedDEK: The wrapped DEK from the manifest
//   - policyBase64: The Base64-encoded policy from the manifest
//   - expectedBindingHash: The policy binding hash from the manifest
//   - authorityPrivateKey: The authority's private key for unwrapping
//   - recipientPublicKey: The recipient's public key for rewrapping
func RewrapWithPolicyVerification(
	wrappedDEK []byte,
	policyBase64 string,
	expectedBindingHash string,
	authorityPrivateKey *rsa.PrivateKey,
	recipientPublicKey *rsa.PublicKey,
) ([]byte, error) {
	// First unwrap to get the DEK
	dek, err := Unwrap(wrappedDEK, authorityPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DEK: %w", err)
	}

	// Verify the policy binding
	if err := VerifyPolicyBinding(dek, policyBase64, expectedBindingHash); err != nil {
		return nil, fmt.Errorf("policy binding verification failed: %w", err)
	}

	// Rewrap for the recipient
	rewrapped, err := Wrap(dek, recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to rewrap DEK: %w", err)
	}

	return rewrapped, nil
}

