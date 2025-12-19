package manifest

// EncryptionInformation aggregates all encryption-related metadata.
type EncryptionInformation struct {
	// Type specifies the key management scheme.
	// "split" is the primary scheme, allowing key sharing across multiple authorities.
	Type string `json:"type"`

	// KeyAccess is an array of KeyAccess objects describing how to obtain the DEK.
	KeyAccess []KeyAccess `json:"keyAccess"`

	// Method describes the symmetric encryption algorithm used on the payload.
	Method Method `json:"method"`

	// IntegrityInformation contains data for verifying payload integrity.
	IntegrityInformation IntegrityInformation `json:"integrityInformation"`

	// Policy is the Base64-encoded JSON string of the Policy object.
	// Contains access control rules for the TDF.
	Policy string `json:"policy"`
}

