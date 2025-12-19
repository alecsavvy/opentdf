package manifest

// Method describes the symmetric encryption algorithm and parameters
// used to encrypt the payload.
type Method struct {
	// Algorithm is the symmetric encryption algorithm.
	// "AES-256-GCM" is the recommended algorithm.
	Algorithm string `json:"algorithm"`

	// IsStreamable indicates if the payload was encrypted in segments
	// suitable for streaming decryption.
	// If true, IntegrityInformation must contain segment details.
	IsStreamable bool `json:"isStreamable"`

	// IV is the Base64-encoded Initialization Vector used with the algorithm.
	// Must be unique for each TDF encrypted with the same key.
	// For AES-GCM, typically 12 bytes (96 bits).
	IV string `json:"iv"`
}

