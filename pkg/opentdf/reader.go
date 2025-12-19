package opentdf

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/opentdf/spec/pkg/crypto"
	"github.com/opentdf/spec/pkg/dek"
	"github.com/opentdf/spec/pkg/manifest"
)

// Reader provides streaming decryption from OpenTDF format.
// Implements io.ReadCloser.
type Reader struct {
	config    DecryptConfig
	manifest  *manifest.Manifest
	decryptor *crypto.SegmentDecryptor

	// Encrypted payload data
	payloadData []byte
	payloadPos  int

	// Segment tracking
	segmentIndex int
	segmentData  []byte // Decrypted data from current segment
	segmentPos   int    // Position within current segment

	// Integrity tracking
	segmentTags [][]byte

	// State
	dek    []byte
	closed bool
}

// NewReader creates a new TDF decryption reader from a byte slice.
// This reads the entire TDF into memory to parse the ZIP structure.
// For very large files, use NewReaderFromFile with a file path.
func NewReader(data []byte, config DecryptConfig) (*Reader, error) {
	if config.PrivateKey == nil {
		return nil, ErrMissingPrivateKey
	}

	// Parse ZIP archive
	zipReader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
	}

	return newReaderFromZip(zipReader, config)
}

// NewReaderFromReadSeeker creates a reader from an io.ReadSeeker (like an os.File).
func NewReaderFromReadSeeker(rs io.ReaderAt, size int64, config DecryptConfig) (*Reader, error) {
	if config.PrivateKey == nil {
		return nil, ErrMissingPrivateKey
	}

	zipReader, err := zip.NewReader(rs, size)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
	}

	return newReaderFromZip(zipReader, config)
}

// newReaderFromZip creates a reader from a parsed ZIP archive.
func newReaderFromZip(zipReader *zip.Reader, config DecryptConfig) (*Reader, error) {
	var manifestFile, payloadFile *zip.File

	for _, f := range zipReader.File {
		switch f.Name {
		case ManifestFilename:
			manifestFile = f
		case PayloadFilename:
			payloadFile = f
		}
	}

	if manifestFile == nil {
		return nil, ErrManifestNotFound
	}
	if payloadFile == nil {
		return nil, ErrPayloadNotFound
	}

	// Read and parse manifest
	manifestReader, err := manifestFile.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open manifest: %w", err)
	}
	defer manifestReader.Close()

	manifestData, err := io.ReadAll(manifestReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	m, err := manifest.FromJSON(manifestData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}

	// Read payload
	payloadReader, err := payloadFile.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open payload: %w", err)
	}
	defer payloadReader.Close()

	payloadData, err := io.ReadAll(payloadReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload: %w", err)
	}

	// Unwrap DEK
	dekBytes, err := unwrapDEK(m, config)
	if err != nil {
		return nil, err
	}

	// Decode IV from manifest
	iv, err := base64.StdEncoding.DecodeString(m.EncryptionInformation.Method.IV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	// Create decryptor
	decryptor, err := crypto.NewSegmentDecryptor(dekBytes, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryptor: %w", err)
	}

	r := &Reader{
		config:       config,
		manifest:     m,
		decryptor:    decryptor,
		payloadData:  payloadData,
		payloadPos:   0,
		segmentIndex: 0,
		segmentTags:  [][]byte{},
		dek:          dekBytes,
	}

	return r, nil
}

// Read implements io.Reader. Decrypts data on demand.
func (r *Reader) Read(p []byte) (n int, err error) {
	if r.closed {
		return 0, ErrReaderClosed
	}

	total := 0

	for len(p) > 0 {
		// If we have data in the current segment buffer, use it
		if r.segmentPos < len(r.segmentData) {
			copied := copy(p, r.segmentData[r.segmentPos:])
			r.segmentPos += copied
			p = p[copied:]
			total += copied
			continue
		}

		// Need to decrypt the next segment
		if r.segmentIndex >= len(r.manifest.EncryptionInformation.IntegrityInformation.Segments) {
			// No more segments
			if total > 0 {
				return total, nil
			}
			return 0, io.EOF
		}

		// Decrypt next segment
		if err := r.decryptNextSegment(); err != nil {
			return total, err
		}
	}

	return total, nil
}

// decryptNextSegment decrypts the next segment from the payload.
func (r *Reader) decryptNextSegment() error {
	segments := r.manifest.EncryptionInformation.IntegrityInformation.Segments
	if r.segmentIndex >= len(segments) {
		return io.EOF
	}

	segment := segments[r.segmentIndex]

	// Determine segment size
	encryptedSize := segment.EncryptedSegmentSize
	if encryptedSize == 0 {
		encryptedSize = r.manifest.EncryptionInformation.IntegrityInformation.EncryptedSegmentSizeDefault
	}

	// Read encrypted segment from payload
	if r.payloadPos+encryptedSize > len(r.payloadData) {
		return fmt.Errorf("payload truncated: expected %d bytes at offset %d", encryptedSize, r.payloadPos)
	}

	ciphertext := r.payloadData[r.payloadPos : r.payloadPos+encryptedSize]
	r.payloadPos += encryptedSize

	// Decrypt segment
	plaintext, err := r.decryptor.DecryptSegment(ciphertext)
	if err != nil {
		return fmt.Errorf("%w: segment %d: %v", ErrIntegrityCheckFailed, r.segmentIndex, err)
	}

	// Store the tag for root signature verification
	tag := ciphertext[len(ciphertext)-crypto.AESGCMTagSize:]
	r.segmentTags = append(r.segmentTags, tag)

	// Verify segment hash matches manifest
	expectedHash := segment.Hash
	actualHash := base64.StdEncoding.EncodeToString(tag)
	if expectedHash != actualHash {
		return fmt.Errorf("%w: segment %d", ErrSegmentHashMismatch, r.segmentIndex)
	}

	r.segmentData = plaintext
	r.segmentPos = 0
	r.segmentIndex++

	return nil
}

// Close releases resources and verifies overall integrity.
func (r *Reader) Close() error {
	if r.closed {
		return ErrReaderClosed
	}
	r.closed = true

	// Decrypt any remaining segments to collect all tags for verification
	for r.segmentIndex < len(r.manifest.EncryptionInformation.IntegrityInformation.Segments) {
		if err := r.decryptNextSegment(); err != nil && err != io.EOF {
			return err
		}
	}

	// Verify root signature
	expectedSig := r.manifest.EncryptionInformation.IntegrityInformation.RootSignature.Signature
	if err := crypto.VerifyRootSignature(r.dek, r.segmentTags, expectedSig); err != nil {
		return ErrRootSignatureMismatch
	}

	// Securely clear DEK from memory
	for i := range r.dek {
		r.dek[i] = 0
	}

	return nil
}

// Manifest returns the parsed manifest.
func (r *Reader) Manifest() *manifest.Manifest {
	return r.manifest
}

// Policy returns the decoded policy from the manifest.
func (r *Reader) Policy() (*manifest.Policy, error) {
	return manifest.PolicyFromBase64(r.manifest.EncryptionInformation.Policy)
}

// ReadAll reads and decrypts the entire payload.
// This is a convenience method that calls Read until EOF and then Close.
func (r *Reader) ReadAll() ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if err := r.Close(); err != nil {
		return nil, err
	}

	return data, nil
}

// unwrapDEK extracts and unwraps the DEK from the manifest.
func unwrapDEK(m *manifest.Manifest, config DecryptConfig) ([]byte, error) {
	keyAccessList := m.EncryptionInformation.KeyAccess
	if len(keyAccessList) == 0 {
		return nil, ErrNoKeyAccess
	}

	// Check if this is a split key scenario
	hasSplits := false
	for _, ka := range keyAccessList {
		if ka.SplitID != "" {
			hasSplits = true
			break
		}
	}

	if hasSplits {
		return unwrapSplitDEK(keyAccessList, config)
	}

	// Single key access - try the first one
	ka := keyAccessList[0]
	return unwrapSingleKey(ka, m.EncryptionInformation.Policy, config)
}

// unwrapSingleKey unwraps a DEK from a single KeyAccess object.
func unwrapSingleKey(ka manifest.KeyAccess, policyBase64 string, config DecryptConfig) ([]byte, error) {
	// Unwrap the DEK
	dekBytes, err := dek.UnwrapFromBase64(ka.WrappedKey, config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DEK: %w", err)
	}

	// Verify policy binding
	if err := dek.VerifyPolicyBinding(dekBytes, policyBase64, ka.PolicyBinding.Hash); err != nil {
		return nil, ErrPolicyBindingMismatch
	}

	return dekBytes, nil
}

// unwrapSplitDEK unwraps and combines key shares from multiple KeyAccess objects.
func unwrapSplitDEK(keyAccessList []manifest.KeyAccess, config DecryptConfig) ([]byte, error) {
	// Collect shares (in a real implementation, you'd need multiple private keys)
	// For now, assume the single private key can unwrap all shares (e.g., same authority)
	shares := make([][]byte, 0, len(keyAccessList))

	for _, ka := range keyAccessList {
		if ka.SplitID == "" {
			continue
		}

		share, err := dek.UnwrapFromBase64(ka.WrappedKey, config.PrivateKey)
		if err != nil {
			// In a real scenario, we might skip shares we can't unwrap
			// if we're only responsible for some shares
			return nil, fmt.Errorf("failed to unwrap key share %s: %w", ka.SplitID, err)
		}

		shares = append(shares, share)
	}

	if len(shares) == 0 {
		return nil, ErrMissingSplitShares
	}

	// Combine shares
	return dek.Combine(shares)
}
