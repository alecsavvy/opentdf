package opentdf

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/opentdf/spec/pkg/crypto"
	"github.com/opentdf/spec/pkg/dek"
	"github.com/opentdf/spec/pkg/manifest"
)

// Writer provides streaming encryption to OpenTDF format.
// Implements io.WriteCloser.
type Writer struct {
	config    EncryptConfig
	manifest  *manifest.Manifest
	dek       []byte
	encryptor *crypto.SegmentEncryptor

	// Buffering for segment-based encryption
	buffer    []byte
	bufferPos int

	// Segment tracking for integrity
	segments     []manifest.Segment
	segmentTags  [][]byte
	bytesWritten int64

	// ZIP archive handling
	zipWriter     *zip.Writer
	payloadWriter io.Writer
	payloadBuffer *bytes.Buffer

	closed bool
}

// NewWriter creates a new TDF encryption writer.
// Data written to this writer will be encrypted and packaged as a TDF.
// Call Close() when done to finalize the archive.
func NewWriter(dst io.Writer, config EncryptConfig) (*Writer, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Generate DEK
	dekBytes, err := dek.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Create segment encryptor
	encryptor, err := crypto.NewSegmentEncryptor(dekBytes, config.segmentSize())
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	// Create manifest
	m := manifest.NewManifest()
	m.Payload.MIMEType = config.mimeType()

	// Set up policy
	policy := config.Policy
	if policy == nil {
		policy = manifest.NewPolicy()
	}
	policyBase64, err := policy.ToBase64()
	if err != nil {
		return nil, fmt.Errorf("failed to encode policy: %w", err)
	}
	m.EncryptionInformation.Policy = policyBase64

	// Set IV in method
	m.EncryptionInformation.Method.IV = base64.StdEncoding.EncodeToString(encryptor.BaseNonce())

	// Set up key access
	if config.SplitConfig != nil {
		// Split DEK across multiple authorities
		keyAccess, err := createSplitKeyAccess(dekBytes, policyBase64, config.SplitConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create split key access: %w", err)
		}
		m.EncryptionInformation.KeyAccess = keyAccess
	} else {
		// Single authority
		keyAccess, err := createKeyAccess(dekBytes, policyBase64, config.Locator, config.AuthorityPublicKey, config.KeyID)
		if err != nil {
			return nil, fmt.Errorf("failed to create key access: %w", err)
		}
		m.EncryptionInformation.KeyAccess = []manifest.KeyAccess{keyAccess}
	}

	// Set segment size defaults
	m.EncryptionInformation.IntegrityInformation.SegmentSizeDefault = config.segmentSize()
	m.EncryptionInformation.IntegrityInformation.EncryptedSegmentSizeDefault = config.encryptedSegmentSize()

	// Add assertions
	if len(config.Assertions) > 0 {
		m.Assertions = config.Assertions
	}

	// Create ZIP writer - we buffer the payload first, then write manifest + payload
	payloadBuffer := new(bytes.Buffer)

	w := &Writer{
		config:        config,
		manifest:      m,
		dek:           dekBytes,
		encryptor:     encryptor,
		buffer:        make([]byte, config.segmentSize()),
		bufferPos:     0,
		segments:      []manifest.Segment{},
		segmentTags:   [][]byte{},
		payloadBuffer: payloadBuffer,
		payloadWriter: payloadBuffer,
	}

	// Store the ZIP writer for finalization
	w.zipWriter = zip.NewWriter(dst)

	return w, nil
}

// Write implements io.Writer. Encrypts data in segments.
func (w *Writer) Write(p []byte) (n int, err error) {
	if w.closed {
		return 0, ErrWriterClosed
	}

	total := 0
	for len(p) > 0 {
		// Fill buffer
		space := len(w.buffer) - w.bufferPos
		toCopy := min(len(p), space)

		copy(w.buffer[w.bufferPos:], p[:toCopy])
		w.bufferPos += toCopy
		p = p[toCopy:]
		total += toCopy

		// If buffer is full, encrypt and flush
		if w.bufferPos == len(w.buffer) {
			if err := w.flushSegment(); err != nil {
				return total, err
			}
		}
	}

	return total, nil
}

// flushSegment encrypts and writes the current buffer as a segment.
func (w *Writer) flushSegment() error {
	if w.bufferPos == 0 {
		return nil
	}

	plaintext := w.buffer[:w.bufferPos]
	plaintextSize := w.bufferPos

	ciphertext, tag, err := w.encryptor.EncryptSegment(plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt segment: %w", err)
	}

	// Write ciphertext to payload buffer
	if _, err := w.payloadWriter.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}

	// Track segment info
	segment := manifest.Segment{
		Hash:                 base64.StdEncoding.EncodeToString(tag),
		SegmentSize:          plaintextSize,
		EncryptedSegmentSize: len(ciphertext),
	}

	// Only include sizes if they differ from defaults
	if plaintextSize == w.config.segmentSize() {
		segment.SegmentSize = 0
	}
	if len(ciphertext) == w.config.encryptedSegmentSize() {
		segment.EncryptedSegmentSize = 0
	}

	w.segments = append(w.segments, segment)
	w.segmentTags = append(w.segmentTags, tag)
	w.bytesWritten += int64(len(ciphertext))

	// Reset buffer
	w.bufferPos = 0

	return nil
}

// Close finalizes the TDF archive.
// This flushes any remaining data, calculates integrity information,
// and writes the manifest and payload to the ZIP archive.
func (w *Writer) Close() error {
	if w.closed {
		return ErrWriterClosed
	}
	w.closed = true

	// Flush any remaining data
	if err := w.flushSegment(); err != nil {
		return err
	}

	// Calculate root signature
	rootSig := crypto.CalculateRootSignature(w.dek, w.segmentTags)
	w.manifest.EncryptionInformation.IntegrityInformation.RootSignature.Signature = rootSig
	w.manifest.EncryptionInformation.IntegrityInformation.Segments = w.segments

	// Write manifest to ZIP
	manifestWriter, err := w.zipWriter.Create(ManifestFilename)
	if err != nil {
		return fmt.Errorf("failed to create manifest in archive: %w", err)
	}

	manifestJSON, err := w.manifest.ToJSONPretty()
	if err != nil {
		return fmt.Errorf("failed to serialize manifest: %w", err)
	}

	if _, err := manifestWriter.Write(manifestJSON); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	// Write payload to ZIP
	payloadZipWriter, err := w.zipWriter.Create(PayloadFilename)
	if err != nil {
		return fmt.Errorf("failed to create payload in archive: %w", err)
	}

	if _, err := payloadZipWriter.Write(w.payloadBuffer.Bytes()); err != nil {
		return fmt.Errorf("failed to write payload: %w", err)
	}

	// Close ZIP archive
	if err := w.zipWriter.Close(); err != nil {
		return fmt.Errorf("failed to close archive: %w", err)
	}

	// Securely clear DEK from memory
	for i := range w.dek {
		w.dek[i] = 0
	}

	return nil
}

// Manifest returns a copy of the manifest (useful after Close for inspection).
func (w *Writer) Manifest() *manifest.Manifest {
	return w.manifest
}

// createKeyAccess creates a single KeyAccess object.
func createKeyAccess(dekBytes []byte, policyBase64, locator string, pubKey *rsa.PublicKey, keyID string) (manifest.KeyAccess, error) {
	// Wrap DEK
	wrappedKey, err := dek.WrapToBase64(dekBytes, pubKey)
	if err != nil {
		return manifest.KeyAccess{}, fmt.Errorf("failed to wrap DEK: %w", err)
	}

	// Calculate policy binding
	bindingHash, err := dek.CalculatePolicyBinding(dekBytes, policyBase64)
	if err != nil {
		return manifest.KeyAccess{}, fmt.Errorf("failed to calculate policy binding: %w", err)
	}

	ka := manifest.NewKeyAccess(locator, wrappedKey, manifest.PolicyBinding{
		Algorithm: manifest.AlgorithmHS256,
		Hash:      bindingHash,
	})
	ka.KeyID = keyID

	return ka, nil
}

// createSplitKeyAccess creates KeyAccess objects for split key configuration.
func createSplitKeyAccess(dekBytes []byte, policyBase64 string, splitConfig *SplitConfig) ([]manifest.KeyAccess, error) {
	// Generate split IDs if needed
	splitIDs := make([]string, len(splitConfig.Authorities))
	for i, auth := range splitConfig.Authorities {
		if auth.SplitID != "" {
			splitIDs[i] = auth.SplitID
		} else {
			splitIDs[i] = uuid.New().String()
		}
	}

	// Split the DEK
	shares, err := dek.SplitWithIDs(dekBytes, splitIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to split DEK: %w", err)
	}

	keyAccessList := make([]manifest.KeyAccess, len(shares))

	for i, share := range shares {
		auth := splitConfig.Authorities[i]

		// Wrap this share
		wrappedShare, err := dek.WrapToBase64(share.Share, auth.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap key share %d: %w", i, err)
		}

		// Calculate policy binding for the share
		bindingHash, err := dek.CalculatePolicyBinding(share.Share, policyBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate policy binding for share %d: %w", i, err)
		}

		ka := manifest.NewKeyAccess(auth.Locator, wrappedShare, manifest.PolicyBinding{
			Algorithm: manifest.AlgorithmHS256,
			Hash:      bindingHash,
		})
		ka.KeyID = auth.KeyID
		ka.SplitID = share.ID

		keyAccessList[i] = ka
	}

	return keyAccessList, nil
}
