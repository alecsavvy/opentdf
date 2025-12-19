package manifest

// KeyAccess describes how to obtain the DEK (or a share of it) from an authority.
// In traditional TDF, the authority is a Key Access Server (KAS).
// In decentralized systems, it could be a chain ID, DID, or other identifier.
type KeyAccess struct {
	// Type specifies how the key is stored/accessed.
	// Values: "wrapped" (default), "remote" (legacy), "remoteWrapped"
	Type string `json:"type"`

	// Locator identifies the key authority.
	// This could be a URL, chain ID, DID, or any system-specific identifier.
	// Maps to "url" in the TDF spec - the base URL of the KAS.
	Locator string `json:"url"`

	// Protocol used to interact with the authority.
	// Currently only "kas" is specified.
	Protocol string `json:"protocol"`

	// WrappedKey is the Base64-encoded DEK (or key share) encrypted with
	// the authority's public key.
	WrappedKey string `json:"wrappedKey"`

	// PolicyBinding contains the cryptographic binding between policy and key.
	PolicyBinding PolicyBinding `json:"policyBinding"`

	// KeyID optionally identifies the specific public key at the authority
	// used to wrap the key. Aids in key rotation.
	// Maps to "kid" in the TDF spec.
	KeyID string `json:"kid,omitempty"`

	// SplitID is a unique identifier for this key share.
	// When present, indicates this is one share of a split key.
	// Multiple KeyAccess objects with different SplitIDs must be combined.
	// Maps to "sid" in the TDF spec.
	SplitID string `json:"sid,omitempty"`

	// EncryptedMetadata is optional Base64-encoded encrypted metadata.
	// Contains client-provided information passed to the authority during rewrap.
	EncryptedMetadata string `json:"encryptedMetadata,omitempty"`
}

// PolicyBinding provides cryptographic binding between the policy and the DEK.
// This prevents policy tampering - the authority verifies this binding
// before releasing the key.
type PolicyBinding struct {
	// Algorithm used to generate the hash.
	// Typically "HS256" (HMAC-SHA256).
	Algorithm string `json:"alg"`

	// Hash is the Base64-encoded HMAC.
	// Calculated as: Base64(HMAC(DEK, Base64EncodedPolicy))
	Hash string `json:"hash"`
}

// NewKeyAccess creates a new KeyAccess with default values.
func NewKeyAccess(locator string, wrappedKey string, policyBinding PolicyBinding) KeyAccess {
	return KeyAccess{
		Type:          KeyAccessTypeWrapped,
		Locator:       locator,
		Protocol:      ProtocolKAS,
		WrappedKey:    wrappedKey,
		PolicyBinding: policyBinding,
	}
}
