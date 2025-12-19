// Package opentdf provides streaming encryption and decryption for OpenTDF format.
// OpenTDF files are ZIP archives containing a manifest.json and encrypted payload.
package opentdf

import (
	"crypto/rsa"

	"github.com/opentdf/spec/pkg/crypto"
	"github.com/opentdf/spec/pkg/manifest"
)

const (
	// DefaultSegmentSize is the default plaintext segment size (1MB).
	DefaultSegmentSize = 1024 * 1024

	// ManifestFilename is the name of the manifest file in the archive.
	ManifestFilename = "manifest.json"

	// PayloadFilename is the default name of the payload file in the archive.
	PayloadFilename = "0.payload"
)

// EncryptConfig contains configuration for TDF encryption.
type EncryptConfig struct {
	// Locator identifies the key authority (maps to "url" in TDF spec).
	// Can be a URL, chain ID, DID, or any system-specific identifier.
	Locator string

	// AuthorityPublicKey is the public key of the authority for DEK wrapping.
	// The DEK will be encrypted (wrapped) with this key.
	AuthorityPublicKey *rsa.PublicKey

	// KeyID optionally identifies a specific key at the authority.
	// Maps to "kid" in the TDF spec.
	KeyID string

	// Policy defines the access control rules.
	// If nil, an empty policy with a generated UUID will be created.
	Policy *manifest.Policy

	// SegmentSize is the plaintext segment size in bytes.
	// Defaults to 1MB if zero.
	SegmentSize int

	// MIMEType specifies the MIME type of the original data.
	// Defaults to "application/octet-stream" if empty.
	MIMEType string

	// Assertions are optional verifiable statements to include.
	Assertions []manifest.Assertion

	// SplitConfig optionally configures key splitting across multiple authorities.
	// If nil, the DEK is wrapped with a single authority.
	SplitConfig *SplitConfig
}

// SplitConfig configures DEK splitting across multiple authorities.
type SplitConfig struct {
	// Authorities defines the authorities that will each hold a key share.
	Authorities []AuthorityConfig
}

// AuthorityConfig defines a single authority for key splitting.
type AuthorityConfig struct {
	// Locator identifies this authority.
	Locator string

	// PublicKey is the authority's public key for wrapping its key share.
	PublicKey *rsa.PublicKey

	// KeyID optionally identifies a specific key at the authority.
	KeyID string

	// SplitID is the unique identifier for this key share.
	// If empty, one will be generated.
	SplitID string
}

// DecryptConfig contains configuration for TDF decryption.
type DecryptConfig struct {
	// PrivateKey is used to unwrap the DEK.
	// This could be the recipient's key (after rewrap) or the authority's key.
	PrivateKey *rsa.PrivateKey
}

// Validate checks the encryption config for required fields.
func (c *EncryptConfig) Validate() error {
	if c.Locator == "" {
		return ErrMissingLocator
	}
	if c.AuthorityPublicKey == nil && c.SplitConfig == nil {
		return ErrMissingPublicKey
	}
	if c.SplitConfig != nil {
		if len(c.SplitConfig.Authorities) < 2 {
			return ErrInvalidSplitConfig
		}
		for i, auth := range c.SplitConfig.Authorities {
			if auth.PublicKey == nil {
				return ErrMissingPublicKey
			}
			if auth.Locator == "" {
				c.SplitConfig.Authorities[i].Locator = c.Locator
			}
		}
	}
	return nil
}

// segmentSize returns the configured segment size or the default.
func (c *EncryptConfig) segmentSize() int {
	if c.SegmentSize <= 0 {
		return DefaultSegmentSize
	}
	return c.SegmentSize
}

// mimeType returns the configured MIME type or the default.
func (c *EncryptConfig) mimeType() string {
	if c.MIMEType == "" {
		return manifest.DefaultMIMEType
	}
	return c.MIMEType
}

// encryptedSegmentSize returns the size of an encrypted segment.
func (c *EncryptConfig) encryptedSegmentSize() int {
	return c.segmentSize() + crypto.AESGCMTagSize
}

