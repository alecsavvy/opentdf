package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// NanoTDFSalt is the salt used for HKDF in NanoTDF key derivation.
// Per NanoTDF spec section 4: SHA256(MAGIC_NUMBER + VERSION)
// For NanoTDF v1 (L1L), this is:
// SHA256([0x4c, 0x31, 0x4c]) = 3de3ca1e50cf62d8b6aba603a96fca6761387a7ac86c3d3afe85ae2d1812edfc
var NanoTDFSalt = []byte{
	0x3d, 0xe3, 0xca, 0x1e, 0x50, 0xcf, 0x62, 0xd8,
	0xb6, 0xab, 0xa6, 0x03, 0xa9, 0x6f, 0xca, 0x67,
	0x61, 0x38, 0x7a, 0x7a, 0xc8, 0x6c, 0x3d, 0x3a,
	0xfe, 0x85, 0xae, 0x2d, 0x18, 0x12, 0xed, 0xfc,
}

// DeriveKey derives a symmetric encryption key from a shared secret using HKDF.
// This is used in NanoTDF for deriving the payload encryption key from ECDH shared secret.
//
// Parameters:
//   - sharedSecret: The ECDH shared secret
//   - salt: The salt for HKDF (use NanoTDFSalt for NanoTDF)
//   - info: Context/application-specific info (can be empty for NanoTDF)
//   - keySize: The desired output key size in bytes (e.g., 32 for AES-256)
func DeriveKey(sharedSecret, salt, info []byte, keySize int) ([]byte, error) {
	// Create HKDF reader with SHA-256
	reader := hkdf.New(sha256.New, sharedSecret, salt, info)

	// Read the derived key
	key := make([]byte, keySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}

	return key, nil
}

// DeriveNanoTDFKey derives a key for NanoTDF encryption from an ECDH shared secret.
// Uses the standard NanoTDF salt and empty info per spec section 4.
func DeriveNanoTDFKey(sharedSecret []byte, keySize int) ([]byte, error) {
	return DeriveKey(sharedSecret, NanoTDFSalt, nil, keySize)
}

// DeriveKeys derives multiple keys from a shared secret.
// Useful when you need both an encryption key and a MAC key.
func DeriveKeys(sharedSecret, salt, info []byte, keySizes ...int) ([][]byte, error) {
	totalSize := 0
	for _, size := range keySizes {
		totalSize += size
	}

	// Derive all key material at once
	reader := hkdf.New(sha256.New, sharedSecret, salt, info)
	material := make([]byte, totalSize)
	if _, err := io.ReadFull(reader, material); err != nil {
		return nil, err
	}

	// Split into individual keys
	keys := make([][]byte, len(keySizes))
	offset := 0
	for i, size := range keySizes {
		keys[i] = make([]byte, size)
		copy(keys[i], material[offset:offset+size])
		offset += size
	}

	return keys, nil
}
