package opentdf

import "errors"

var (
	// Configuration errors
	ErrMissingLocator     = errors.New("locator is required")
	ErrMissingPublicKey   = errors.New("authority public key is required")
	ErrMissingPrivateKey  = errors.New("private key is required")
	ErrInvalidSplitConfig = errors.New("split config requires at least 2 authorities")

	// Archive errors
	ErrInvalidArchive      = errors.New("invalid TDF archive")
	ErrManifestNotFound    = errors.New("manifest.json not found in archive")
	ErrPayloadNotFound     = errors.New("payload not found in archive")
	ErrInvalidManifest     = errors.New("invalid manifest format")
	ErrNoKeyAccess         = errors.New("no key access objects in manifest")
	ErrKeyAccessNotFound   = errors.New("matching key access object not found")
	ErrMissingSplitShares  = errors.New("not all required key shares available")

	// Integrity errors
	ErrIntegrityCheckFailed   = errors.New("integrity check failed")
	ErrSegmentHashMismatch    = errors.New("segment hash does not match")
	ErrRootSignatureMismatch  = errors.New("root signature does not match")
	ErrPolicyBindingMismatch  = errors.New("policy binding verification failed")

	// State errors
	ErrWriterClosed = errors.New("writer is closed")
	ErrReaderClosed = errors.New("reader is closed")
)

