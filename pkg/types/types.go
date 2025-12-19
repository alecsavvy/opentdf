// Package types provides shared types for the OpenTDF library.
package types

import (
	"crypto/ecdsa"
	"crypto/rsa"
)

// KeyPair represents a generic key pair for encryption operations.
type KeyPair struct {
	// RSA keys for OpenTDF format
	RSAPrivateKey *rsa.PrivateKey
	RSAPublicKey  *rsa.PublicKey

	// ECC keys for NanoTDF format
	ECCPrivateKey *ecdsa.PrivateKey
	ECCPublicKey  *ecdsa.PublicKey
}

// HasRSA returns true if RSA keys are available.
func (kp *KeyPair) HasRSA() bool {
	return kp.RSAPrivateKey != nil || kp.RSAPublicKey != nil
}

// HasECC returns true if ECC keys are available.
func (kp *KeyPair) HasECC() bool {
	return kp.ECCPrivateKey != nil || kp.ECCPublicKey != nil
}

