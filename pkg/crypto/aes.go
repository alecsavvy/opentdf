// Package crypto provides cryptographic primitives for OpenTDF encryption and decryption.
// This package is internal to the opentdf library.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

const (
	// AESKeySize is the key size for AES-256 in bytes.
	AESKeySize = 32

	// AESGCMNonceSize is the standard nonce size for AES-GCM (96 bits).
	AESGCMNonceSize = 12

	// AESGCMTagSize is the authentication tag size for AES-GCM (128 bits).
	AESGCMTagSize = 16

	// DefaultSegmentSize is the default plaintext segment size (1MB).
	DefaultSegmentSize = 1024 * 1024
)

var (
	ErrInvalidKeySize   = errors.New("invalid key size: must be 32 bytes for AES-256")
	ErrInvalidNonceSize = errors.New("invalid nonce size")
	ErrDecryptionFailed = errors.New("decryption failed: authentication error")
)

// GenerateNonce generates a cryptographically secure random nonce for AES-GCM.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, AESGCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// NewAESGCM creates a new AES-GCM cipher.AEAD from a 256-bit key.
func NewAESGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != AESKeySize {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return aead, nil
}

// EncryptAESGCM encrypts plaintext using AES-256-GCM.
// Returns ciphertext with the authentication tag appended.
// The nonce must be unique for each encryption with the same key.
func EncryptAESGCM(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	aead, err := NewAESGCM(key)
	if err != nil {
		return nil, err
	}

	if len(nonce) != AESGCMNonceSize {
		return nil, ErrInvalidNonceSize
	}

	// Seal appends the ciphertext and tag to dst
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// DecryptAESGCM decrypts ciphertext using AES-256-GCM.
// The ciphertext must include the authentication tag (last 16 bytes).
// Returns the plaintext if authentication succeeds.
func DecryptAESGCM(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	aead, err := NewAESGCM(key)
	if err != nil {
		return nil, err
	}

	if len(nonce) != AESGCMNonceSize {
		return nil, ErrInvalidNonceSize
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// EncryptedSegmentSize calculates the size of an encrypted segment
// given the plaintext segment size.
func EncryptedSegmentSize(plaintextSize int) int {
	return plaintextSize + AESGCMTagSize
}

// SegmentEncryptor handles streaming encryption of data in segments.
type SegmentEncryptor struct {
	key         []byte
	aead        cipher.AEAD
	segmentSize int
	nonceBase   []byte // Base nonce, incremented per segment
	segmentNum  uint64
}

// NewSegmentEncryptor creates a new segment encryptor for streaming encryption.
func NewSegmentEncryptor(key []byte, segmentSize int) (*SegmentEncryptor, error) {
	aead, err := NewAESGCM(key)
	if err != nil {
		return nil, err
	}

	if segmentSize <= 0 {
		segmentSize = DefaultSegmentSize
	}

	// Generate base nonce
	nonceBase, err := GenerateNonce()
	if err != nil {
		return nil, err
	}

	return &SegmentEncryptor{
		key:         key,
		aead:        aead,
		segmentSize: segmentSize,
		nonceBase:   nonceBase,
		segmentNum:  0,
	}, nil
}

// SegmentSize returns the configured plaintext segment size.
func (e *SegmentEncryptor) SegmentSize() int {
	return e.segmentSize
}

// BaseNonce returns the base nonce used for this encryptor.
// This should be stored in the manifest for decryption.
func (e *SegmentEncryptor) BaseNonce() []byte {
	nonce := make([]byte, len(e.nonceBase))
	copy(nonce, e.nonceBase)
	return nonce
}

// nonceForSegment derives a unique nonce for a specific segment number.
// Uses XOR of segment number with the last bytes of the base nonce.
func (e *SegmentEncryptor) nonceForSegment(segmentNum uint64) []byte {
	nonce := make([]byte, AESGCMNonceSize)
	copy(nonce, e.nonceBase)

	// XOR the segment number into the last 8 bytes of the nonce
	for i := 0; i < 8; i++ {
		nonce[AESGCMNonceSize-1-i] ^= byte(segmentNum >> (i * 8))
	}

	return nonce
}

// EncryptSegment encrypts a single segment of data.
// Returns the ciphertext (including auth tag) and the segment's authentication tag.
func (e *SegmentEncryptor) EncryptSegment(plaintext []byte) (ciphertext []byte, tag []byte, err error) {
	nonce := e.nonceForSegment(e.segmentNum)
	e.segmentNum++

	ciphertext = e.aead.Seal(nil, nonce, plaintext, nil)

	// Extract the tag (last 16 bytes)
	tag = ciphertext[len(ciphertext)-AESGCMTagSize:]

	return ciphertext, tag, nil
}

// SegmentDecryptor handles streaming decryption of data in segments.
type SegmentDecryptor struct {
	key        []byte
	aead       cipher.AEAD
	nonceBase  []byte
	segmentNum uint64
}

// NewSegmentDecryptor creates a new segment decryptor for streaming decryption.
func NewSegmentDecryptor(key []byte, nonceBase []byte) (*SegmentDecryptor, error) {
	aead, err := NewAESGCM(key)
	if err != nil {
		return nil, err
	}

	if len(nonceBase) != AESGCMNonceSize {
		return nil, ErrInvalidNonceSize
	}

	nonce := make([]byte, len(nonceBase))
	copy(nonce, nonceBase)

	return &SegmentDecryptor{
		key:        key,
		aead:       aead,
		nonceBase:  nonce,
		segmentNum: 0,
	}, nil
}

// nonceForSegment derives a unique nonce for a specific segment number.
func (d *SegmentDecryptor) nonceForSegment(segmentNum uint64) []byte {
	nonce := make([]byte, AESGCMNonceSize)
	copy(nonce, d.nonceBase)

	// XOR the segment number into the last 8 bytes of the nonce
	for i := 0; i < 8; i++ {
		nonce[AESGCMNonceSize-1-i] ^= byte(segmentNum >> (i * 8))
	}

	return nonce
}

// DecryptSegment decrypts a single segment of data.
// The ciphertext must include the authentication tag.
func (d *SegmentDecryptor) DecryptSegment(ciphertext []byte) ([]byte, error) {
	nonce := d.nonceForSegment(d.segmentNum)
	d.segmentNum++

	plaintext, err := d.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// DecryptSegmentAt decrypts a segment at a specific index (for random access).
func (d *SegmentDecryptor) DecryptSegmentAt(ciphertext []byte, segmentIndex uint64) ([]byte, error) {
	nonce := d.nonceForSegment(segmentIndex)

	plaintext, err := d.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

