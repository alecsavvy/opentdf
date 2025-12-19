package nanotdf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/opentdf/spec/pkg/crypto"
)

// Writer errors
var (
	ErrMissingRecipientKey = errors.New("recipient public key is required")
	ErrMissingLocator      = errors.New("locator is required")
	ErrPayloadTooLarge     = errors.New("payload exceeds maximum size (16MB)")
	ErrWriterClosed        = errors.New("writer is closed")
)

// MaxPayloadSize is the maximum NanoTDF payload size (24-bit length = 16MB)
const MaxPayloadSize = 16777215

// Config contains configuration for NanoTDF encryption.
type Config struct {
	// Locator identifies the key authority (maps to KAS in TDF spec).
	// Can be a URL, chain ID, DID, or any system-specific identifier.
	Locator string

	// LocatorProtocol is the protocol for the locator (default: HTTPS)
	LocatorProtocol ProtocolEnum

	// RecipientPublicKey is the authority's public key for ECDH.
	// The symmetric key is derived from ECDH with this key.
	RecipientPublicKey *ecdsa.PublicKey

	// ECCMode specifies the elliptic curve (default: secp256r1)
	ECCMode ECCMode

	// SymmetricCipher specifies the AES-GCM tag size (default: 128-bit)
	SymmetricCipher SymmetricCipher

	// Policy is the policy data (optional, for embedded policies)
	Policy []byte

	// PolicyType specifies how the policy is stored (default: remote)
	PolicyType PolicyType

	// PolicyLocator for remote policies (if PolicyType == PolicyTypeRemote)
	PolicyLocator *ResourceLocator

	// UseECDSABinding uses ECDSA for policy binding instead of GMAC
	UseECDSABinding bool

	// SigningKey for creator signatures (optional)
	SigningKey *ecdsa.PrivateKey

	// SignatureECCMode for the creator signature (if SigningKey is set)
	SignatureECCMode ECCMode
}

// Writer provides NanoTDF encryption.
type Writer struct {
	config    Config
	dst       io.Writer
	buffer    bytes.Buffer
	header    *Header
	dek       []byte
	ephemeral *ecdsa.PrivateKey
	closed    bool
}

// NewWriter creates a new NanoTDF encryption writer.
func NewWriter(dst io.Writer, config Config) (*Writer, error) {
	if config.Locator == "" {
		return nil, ErrMissingLocator
	}
	if config.RecipientPublicKey == nil {
		return nil, ErrMissingRecipientKey
	}

	// Set defaults
	if config.LocatorProtocol == 0 {
		config.LocatorProtocol = ProtocolHTTPS
	}
	if config.SymmetricCipher == 0 {
		config.SymmetricCipher = CipherAES256GCM128
	}

	// Validate ECC mode
	curve, err := crypto.CurveForMode(config.ECCMode)
	if err != nil {
		return nil, fmt.Errorf("invalid ECC mode: %w", err)
	}

	// Generate ephemeral key pair on the same curve as recipient
	ephemeral, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Perform ECDH to derive shared secret
	sharedSecret, err := crypto.ECDH(ephemeral, config.RecipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive symmetric key using HKDF
	dek, err := crypto.DeriveNanoTDFKey(sharedSecret, 32) // AES-256
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Compress ephemeral public key
	compressedKey, err := crypto.CompressPublicKey(&ephemeral.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compress ephemeral key: %w", err)
	}

	w := &Writer{
		config:    config,
		dst:       dst,
		dek:       dek,
		ephemeral: ephemeral,
		header: &Header{
			Version:            Version12,
			Locator:            NewResourceLocator(config.Locator, config.LocatorProtocol),
			ECCMode:            config.ECCMode,
			UseECDSABinding:    config.UseECDSABinding,
			SymmetricCipher:    config.SymmetricCipher,
			HasSignature:       config.SigningKey != nil,
			SignatureECCMode:   config.SignatureECCMode,
			EphemeralPublicKey: compressedKey,
		},
	}

	return w, nil
}

// Write buffers plaintext data for encryption.
func (w *Writer) Write(p []byte) (n int, err error) {
	if w.closed {
		return 0, ErrWriterClosed
	}

	if w.buffer.Len()+len(p) > MaxPayloadSize {
		return 0, ErrPayloadTooLarge
	}

	return w.buffer.Write(p)
}

// Close encrypts the buffered data and writes the complete NanoTDF.
func (w *Writer) Close() error {
	if w.closed {
		return ErrWriterClosed
	}
	w.closed = true

	plaintext := w.buffer.Bytes()

	// Set up policy
	if err := w.setupPolicy(); err != nil {
		return fmt.Errorf("failed to setup policy: %w", err)
	}

	// Encrypt payload
	ciphertext, iv, err := w.encryptPayload(plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt payload: %w", err)
	}

	// Marshal header
	headerBytes, err := w.header.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}

	// Write header
	if _, err := w.dst.Write(headerBytes); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write payload section
	payloadLen := len(iv) + len(ciphertext)

	// Payload length (3 bytes, big endian)
	lenBytes := []byte{
		byte(payloadLen >> 16),
		byte(payloadLen >> 8),
		byte(payloadLen),
	}
	if _, err := w.dst.Write(lenBytes); err != nil {
		return fmt.Errorf("failed to write payload length: %w", err)
	}

	// IV (3 bytes)
	if _, err := w.dst.Write(iv); err != nil {
		return fmt.Errorf("failed to write IV: %w", err)
	}

	// Ciphertext + tag
	if _, err := w.dst.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}

	// Write signature if configured
	if w.config.SigningKey != nil {
		if err := w.writeSignature(headerBytes, lenBytes, iv, ciphertext); err != nil {
			return fmt.Errorf("failed to write signature: %w", err)
		}
	}

	// Clear sensitive data
	for i := range w.dek {
		w.dek[i] = 0
	}

	return nil
}

// setupPolicy prepares the policy section of the header.
func (w *Writer) setupPolicy() error {
	switch w.config.PolicyType {
	case PolicyTypeRemote:
		if w.config.PolicyLocator == nil {
			// Use default policy locator based on main locator
			w.header.Policy = Policy{
				Type: PolicyTypeRemote,
				Remote: &ResourceLocator{
					Protocol: w.config.LocatorProtocol,
					Body:     w.config.Locator + "/policy",
				},
			}
		} else {
			w.header.Policy = Policy{
				Type:   PolicyTypeRemote,
				Remote: w.config.PolicyLocator,
			}
		}

	case PolicyTypeEmbeddedPlaintext:
		w.header.Policy = Policy{
			Type: PolicyTypeEmbeddedPlaintext,
			Body: w.config.Policy,
		}

	case PolicyTypeEmbeddedEncrypted:
		// Encrypt policy with DEK using IV = 0x000000 as per spec
		encryptedPolicy, err := w.encryptPolicyBody(w.config.Policy)
		if err != nil {
			return err
		}
		w.header.Policy = Policy{
			Type: PolicyTypeEmbeddedEncrypted,
			Body: encryptedPolicy,
		}

	default:
		// Default to remote
		w.header.Policy = Policy{
			Type: PolicyTypeRemote,
			Remote: &ResourceLocator{
				Protocol: w.config.LocatorProtocol,
				Body:     w.config.Locator + "/policy",
			},
		}
	}

	// Calculate policy binding
	binding, err := w.calculatePolicyBinding()
	if err != nil {
		return err
	}
	w.header.Policy.Binding = binding

	return nil
}

// calculatePolicyBinding computes the binding between policy and DEK.
func (w *Writer) calculatePolicyBinding() ([]byte, error) {
	// Get policy body bytes for binding
	var policyBytes []byte
	switch w.header.Policy.Type {
	case PolicyTypeRemote:
		// Marshal the resource locator for binding
		var buf bytes.Buffer
		if err := writeResourceLocator(&buf, *w.header.Policy.Remote); err != nil {
			return nil, err
		}
		policyBytes = buf.Bytes()
	default:
		policyBytes = w.header.Policy.Body
	}

	// Hash the policy body
	policyHash := sha256.Sum256(policyBytes)

	if w.config.UseECDSABinding {
		// Sign with ephemeral private key
		sig, err := crypto.SignECDSA(w.ephemeral, policyHash[:])
		if err != nil {
			return nil, err
		}
		return sig, nil
	}

	// Use GMAC (first 8 bytes of AES-GCM tag)
	block, err := aes.NewCipher(w.dek)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Use zero nonce for binding GMAC
	nonce := make([]byte, aead.NonceSize())
	tag := aead.Seal(nil, nonce, nil, policyHash[:])

	// Return first 8 bytes as GMAC
	return tag[:8], nil
}

// encryptPayload encrypts the plaintext using AES-GCM.
func (w *Writer) encryptPayload(plaintext []byte) (ciphertext, iv []byte, err error) {
	block, err := aes.NewCipher(w.dek)
	if err != nil {
		return nil, nil, err
	}

	// Create GCM with custom tag size
	tagSize := w.config.SymmetricCipher.TagSize()
	aead, err := cipher.NewGCMWithTagSize(block, tagSize)
	if err != nil {
		return nil, nil, err
	}

	// Generate 3-byte IV (NanoTDF uses truncated IV)
	iv = make([]byte, NanoTDFIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}

	// Pad IV to GCM nonce size (12 bytes)
	nonce := make([]byte, aead.NonceSize())
	copy(nonce[aead.NonceSize()-NanoTDFIVSize:], iv)

	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, iv, nil
}

// encryptPolicyBody encrypts the policy using IV = 0x000000 as per spec.
func (w *Writer) encryptPolicyBody(policy []byte) ([]byte, error) {
	block, err := aes.NewCipher(w.dek)
	if err != nil {
		return nil, err
	}

	tagSize := w.config.SymmetricCipher.TagSize()
	aead, err := cipher.NewGCMWithTagSize(block, tagSize)
	if err != nil {
		return nil, err
	}

	// Use zero IV for policy encryption as per spec
	nonce := make([]byte, aead.NonceSize())

	return aead.Seal(nil, nonce, policy, nil), nil
}

// writeSignature writes the creator signature section.
func (w *Writer) writeSignature(header, payloadLen, iv, ciphertext []byte) error {
	// Concatenate all data for signing
	var toSign bytes.Buffer
	toSign.Write(header)
	toSign.Write(payloadLen)
	toSign.Write(iv)
	toSign.Write(ciphertext)

	// Hash and sign
	hash := crypto.HashForSigning(toSign.Bytes())
	sig, err := crypto.SignECDSA(w.config.SigningKey, hash)
	if err != nil {
		return err
	}

	// Compress signing public key
	sigPubKey, err := crypto.CompressPublicKey(&w.config.SigningKey.PublicKey)
	if err != nil {
		return err
	}

	// Write public key
	if _, err := w.dst.Write(sigPubKey); err != nil {
		return err
	}

	// Write signature
	if _, err := w.dst.Write(sig); err != nil {
		return err
	}

	return nil
}

// Encrypt is a convenience function to encrypt data to NanoTDF format.
func Encrypt(plaintext []byte, config Config) ([]byte, error) {
	var buf bytes.Buffer

	w, err := NewWriter(&buf, config)
	if err != nil {
		return nil, err
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
