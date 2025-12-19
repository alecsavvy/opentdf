package manifest

// IntegrityInformation provides mechanisms to verify payload integrity.
// Essential for streaming and detecting tampering.
type IntegrityInformation struct {
	// RootSignature is a cryptographic signature over all segment hashes.
	RootSignature RootSignature `json:"rootSignature"`

	// SegmentHashAlgorithm is the algorithm used to generate segment hashes.
	// "GMAC" is commonly used with AES-256-GCM.
	SegmentHashAlgorithm string `json:"segmentHashAlg"`

	// Segments is an array of segment integrity information.
	// One entry per payload segment, in order.
	Segments []Segment `json:"segments"`

	// SegmentSizeDefault is the default plaintext segment size in bytes.
	SegmentSizeDefault int `json:"segmentSizeDefault"`

	// EncryptedSegmentSizeDefault is the default encrypted segment size in bytes.
	// Includes authentication tag overhead (e.g., 16 bytes for AES-GCM).
	EncryptedSegmentSizeDefault int `json:"encryptedSegmentSizeDefault"`
}

// RootSignature contains the overall payload integrity signature.
type RootSignature struct {
	// Algorithm used for the signature.
	// "HS256" (HMAC-SHA256) is commonly used.
	Algorithm string `json:"alg"`

	// Signature is the Base64-encoded signature.
	// Calculated as: Base64(HMAC-SHA256(DEK, Concat(SegmentHash1, SegmentHash2, ...)))
	Signature string `json:"sig"`
}

// Segment contains integrity information for a single payload segment.
type Segment struct {
	// Hash is the Base64-encoded hash/tag for this segment.
	// For GMAC, this is the AES-GCM authentication tag.
	Hash string `json:"hash"`

	// SegmentSize is the plaintext size of this segment in bytes.
	// Optional if it matches SegmentSizeDefault.
	SegmentSize int `json:"segmentSize,omitempty"`

	// EncryptedSegmentSize is the ciphertext size in bytes.
	// Includes the authentication tag.
	EncryptedSegmentSize int `json:"encryptedSegmentSize,omitempty"`
}

