package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	// MinRSAKeySize is the minimum supported RSA key size in bits.
	MinRSAKeySize = 2048
)

var (
	ErrRSAKeyTooSmall = errors.New("RSA key size too small: minimum 2048 bits required")
	ErrRSADecryption  = errors.New("RSA decryption failed")
)

// WrapKeyRSA wraps (encrypts) a symmetric key using RSA-OAEP with SHA-256.
// This is used to wrap DEKs with an authority's public key.
// In the TDF spec, this corresponds to wrapping the DEK with the KAS public key.
func WrapKeyRSA(symmetricKey []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("public key is nil")
	}

	if publicKey.Size()*8 < MinRSAKeySize {
		return nil, ErrRSAKeyTooSmall
	}

	// Use SHA-256 for OAEP
	hash := sha256.New()

	// Label can be empty for standard OAEP
	label := []byte{}

	wrapped, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, symmetricKey, label)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
	}

	return wrapped, nil
}

// UnwrapKeyRSA unwraps (decrypts) a symmetric key using RSA-OAEP with SHA-256.
// This is used to unwrap DEKs with an authority's private key.
// In the TDF spec, this corresponds to unwrapping the DEK with the KAS private key.
func UnwrapKeyRSA(wrappedKey []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	if privateKey.Size()*8 < MinRSAKeySize {
		return nil, ErrRSAKeyTooSmall
	}

	// Use SHA-256 for OAEP
	hash := sha256.New()

	// Label must match what was used during encryption
	label := []byte{}

	unwrapped, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, wrappedKey, label)
	if err != nil {
		return nil, ErrRSADecryption
	}

	return unwrapped, nil
}

// RewrapKeyRSA rewraps a DEK for a different recipient.
// It first unwraps the DEK using the authority's private key,
// then wraps it with the recipient's public key.
// This is the core operation performed by a key access service during rewrap.
func RewrapKeyRSA(wrappedKey []byte, authorityPrivateKey *rsa.PrivateKey, recipientPublicKey *rsa.PublicKey) ([]byte, error) {
	// First unwrap with authority's private key
	dek, err := UnwrapKeyRSA(wrappedKey, authorityPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	// Then wrap with recipient's public key
	rewrapped, err := WrapKeyRSA(dek, recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to rewrap key: %w", err)
	}

	return rewrapped, nil
}

// GenerateRSAKeyPair generates a new RSA key pair with the specified bit size.
// Supported sizes: 2048, 3072, 4096 bits.
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	if bits < MinRSAKeySize {
		return nil, ErrRSAKeyTooSmall
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	return privateKey, nil
}

