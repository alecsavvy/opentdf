package nanotdf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/opentdf/spec/pkg/crypto"
)

// Reader errors
var (
	ErrMissingPrivateKey       = errors.New("recipient private key is required")
	ErrInvalidPayload          = errors.New("invalid payload format")
	ErrDecryptionFailed        = errors.New("decryption failed")
	ErrPolicyBindingFailed     = errors.New("policy binding verification failed")
	ErrSignatureInvalid        = errors.New("creator signature is invalid")
	ErrReaderClosed            = errors.New("reader is closed")
)

// Reader provides NanoTDF decryption.
type Reader struct {
	header      *Header
	plaintext   []byte
	pos         int
	closed      bool
}

// NewReader creates a new NanoTDF decryption reader.
// The recipientPrivateKey is the authority's private key for ECDH key derivation.
func NewReader(data []byte, recipientPrivateKey *ecdsa.PrivateKey) (*Reader, error) {
	if recipientPrivateKey == nil {
		return nil, ErrMissingPrivateKey
	}

	r := bytes.NewReader(data)

	// Parse header
	header, err := ParseHeader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Get ephemeral public key from header
	ephemeralPub, err := header.GetEphemeralPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to parse ephemeral key: %w", err)
	}

	// Perform ECDH to derive shared secret
	sharedSecret, err := crypto.ECDH(recipientPrivateKey, ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %w", err)
	}

	// Derive symmetric key using HKDF
	dek, err := crypto.DeriveNanoTDFKey(sharedSecret, 32)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Verify policy binding
	if err := verifyPolicyBinding(header, dek, ephemeralPub); err != nil {
		return nil, err
	}

	// Read payload length (3 bytes)
	lenBytes := make([]byte, PayloadLengthSize)
	if _, err := io.ReadFull(r, lenBytes); err != nil {
		return nil, fmt.Errorf("%w: payload length", ErrInvalidPayload)
	}
	payloadLen := int(lenBytes[0])<<16 | int(lenBytes[1])<<8 | int(lenBytes[2])

	// Read IV + ciphertext
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("%w: payload data", ErrInvalidPayload)
	}

	// Extract IV and ciphertext
	if len(payload) < NanoTDFIVSize {
		return nil, fmt.Errorf("%w: payload too short", ErrInvalidPayload)
	}
	iv := payload[:NanoTDFIVSize]
	ciphertext := payload[NanoTDFIVSize:]

	// Decrypt payload
	plaintext, err := decryptPayload(dek, iv, ciphertext, header.SymmetricCipher)
	if err != nil {
		return nil, err
	}

	// Verify signature if present
	if header.HasSignature {
		// Read signature section
		sigKeySize := crypto.CompressedPublicKeySize(header.SignatureECCMode)
		sigSize := crypto.SignatureSize(header.SignatureECCMode)

		sigData := make([]byte, sigKeySize+sigSize)
		if _, err := io.ReadFull(r, sigData); err != nil {
			// Signature might be optional in some cases
			if err != io.EOF {
				return nil, fmt.Errorf("failed to read signature: %w", err)
			}
		} else {
			// Verify signature
			sigPubKeyBytes := sigData[:sigKeySize]
			signature := sigData[sigKeySize:]

			if err := verifySignature(data, header, sigPubKeyBytes, signature); err != nil {
				return nil, err
			}
		}
	}

	// Clear DEK
	for i := range dek {
		dek[i] = 0
	}

	return &Reader{
		header:    header,
		plaintext: plaintext,
		pos:       0,
	}, nil
}

// Read implements io.Reader.
func (r *Reader) Read(p []byte) (n int, err error) {
	if r.closed {
		return 0, ErrReaderClosed
	}

	if r.pos >= len(r.plaintext) {
		return 0, io.EOF
	}

	n = copy(p, r.plaintext[r.pos:])
	r.pos += n
	return n, nil
}

// Close releases resources.
func (r *Reader) Close() error {
	if r.closed {
		return ErrReaderClosed
	}
	r.closed = true
	return nil
}

// Header returns the parsed NanoTDF header.
func (r *Reader) Header() *Header {
	return r.header
}

// ReadAll returns the complete decrypted plaintext.
func (r *Reader) ReadAll() ([]byte, error) {
	result := make([]byte, len(r.plaintext))
	copy(result, r.plaintext)
	return result, nil
}

// verifyPolicyBinding verifies the policy binding in the header.
func verifyPolicyBinding(header *Header, dek []byte, ephemeralPub *ecdsa.PublicKey) error {
	// Get policy body bytes
	var policyBytes []byte
	switch header.Policy.Type {
	case PolicyTypeRemote:
		if header.Policy.Remote != nil {
			var buf bytes.Buffer
			if err := writeResourceLocator(&buf, *header.Policy.Remote); err != nil {
				return err
			}
			policyBytes = buf.Bytes()
		}
	default:
		policyBytes = header.Policy.Body
	}

	// Hash the policy body
	policyHash := sha256.Sum256(policyBytes)

	if header.UseECDSABinding {
		// Verify ECDSA signature using ephemeral public key
		if !crypto.VerifyECDSA(ephemeralPub, policyHash[:], header.Policy.Binding) {
			return ErrPolicyBindingFailed
		}
		return nil
	}

	// Verify GMAC
	block, err := aes.NewCipher(dek)
	if err != nil {
		return err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Compute expected GMAC
	nonce := make([]byte, aead.NonceSize())
	tag := aead.Seal(nil, nonce, nil, policyHash[:])

	// Compare first 8 bytes
	if !bytes.Equal(tag[:8], header.Policy.Binding) {
		return ErrPolicyBindingFailed
	}

	return nil
}

// decryptPayload decrypts the NanoTDF payload.
func decryptPayload(dek, iv, ciphertext []byte, cipher SymmetricCipher) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}

	tagSize := cipher.TagSize()
	aead, err := gcmWithTagSize(block, tagSize)
	if err != nil {
		return nil, err
	}

	// Pad IV to GCM nonce size
	nonce := make([]byte, aead.NonceSize())
	copy(nonce[aead.NonceSize()-NanoTDFIVSize:], iv)

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// gcmWithTagSize creates a GCM cipher with a specific tag size.
func gcmWithTagSize(block cipher.Block, tagSize int) (cipher.AEAD, error) {
	return cipher.NewGCMWithTagSize(block, tagSize)
}

// verifySignature verifies the creator signature.
func verifySignature(fullData []byte, header *Header, sigPubKeyBytes, signature []byte) error {
	// Parse the signing public key
	curve, err := crypto.CurveForMode(header.SignatureECCMode)
	if err != nil {
		return err
	}

	sigPubKey, err := crypto.UnmarshalPublicKey(curve, sigPubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse signature public key: %w", err)
	}

	// Calculate what was signed (header + payload, excluding signature section)
	// We need to find where the signature starts
	sigKeySize := crypto.CompressedPublicKeySize(header.SignatureECCMode)
	sigSize := crypto.SignatureSize(header.SignatureECCMode)
	signedData := fullData[:len(fullData)-sigKeySize-sigSize]

	hash := crypto.HashForSigning(signedData)

	if !crypto.VerifyECDSA(sigPubKey, hash, signature) {
		return ErrSignatureInvalid
	}

	return nil
}

// Decrypt is a convenience function to decrypt NanoTDF data.
func Decrypt(data []byte, recipientPrivateKey *ecdsa.PrivateKey) ([]byte, error) {
	r, err := NewReader(data, recipientPrivateKey)
	if err != nil {
		return nil, err
	}

	return r.ReadAll()
}

