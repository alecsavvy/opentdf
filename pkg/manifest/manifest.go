// Package manifest defines the JSON structures for OpenTDF manifests.
// This package provides types that serialize to/from the TDF manifest.json format.
//
// Naming Convention:
// Go struct fields use agnostic naming (e.g., "Locator" instead of "URL",
// "Authority" concepts instead of "KAS") to support decentralized systems.
// JSON field names match the TDF specification for wire compatibility.
package manifest

import (
	"encoding/json"
)

const (
	// TDFSpecVersion is the current TDF specification version.
	TDFSpecVersion = "4.3.0"

	// EncryptionTypeSplit indicates the key management scheme uses key splitting.
	// This is the primary scheme in OpenTDF.
	EncryptionTypeSplit = "split"

	// KeyAccessTypeWrapped indicates the DEK is wrapped (encrypted) with the authority's key.
	KeyAccessTypeWrapped = "wrapped"

	// KeyAccessTypeRemote indicates the key is stored remotely (legacy).
	KeyAccessTypeRemote = "remote"

	// ProtocolKAS is the standard protocol for key access.
	// Maps to "kas" in the TDF spec.
	ProtocolKAS = "kas"

	// PayloadTypeReference indicates the payload is referenced within the archive.
	PayloadTypeReference = "reference"

	// PayloadProtocolZip indicates standard ZIP packaging.
	PayloadProtocolZip = "zip"

	// PayloadProtocolZipStream indicates streaming ZIP packaging.
	PayloadProtocolZipStream = "zipstream"

	// DefaultPayloadFilename is the standard payload filename in the archive.
	DefaultPayloadFilename = "0.payload"

	// DefaultMIMEType is used when no MIME type is specified.
	DefaultMIMEType = "application/octet-stream"

	// AlgorithmAES256GCM is the standard encryption algorithm.
	AlgorithmAES256GCM = "AES-256-GCM"

	// AlgorithmHS256 is HMAC-SHA256 for policy binding.
	AlgorithmHS256 = "HS256"

	// AlgorithmGMAC is used for segment hashing with AES-GCM.
	AlgorithmGMAC = "GMAC"
)

// Manifest represents the complete TDF manifest.json structure.
type Manifest struct {
	// TDFSpecVersion is the semver version of the TDF specification.
	TDFSpecVersion string `json:"tdf_spec_version"`

	// Payload describes the encrypted payload location and characteristics.
	Payload Payload `json:"payload"`

	// EncryptionInformation contains key access, method, integrity, and policy details.
	EncryptionInformation EncryptionInformation `json:"encryptionInformation"`

	// Assertions contains optional verifiable statements about the TDF.
	Assertions []Assertion `json:"assertions,omitempty"`
}

// NewManifest creates a new manifest with default values.
func NewManifest() *Manifest {
	return &Manifest{
		TDFSpecVersion: TDFSpecVersion,
		Payload: Payload{
			Type:        PayloadTypeReference,
			Reference:   DefaultPayloadFilename,
			Protocol:    PayloadProtocolZip,
			IsEncrypted: true,
			MIMEType:    DefaultMIMEType,
		},
		EncryptionInformation: EncryptionInformation{
			Type:      EncryptionTypeSplit,
			KeyAccess: []KeyAccess{},
			Method: Method{
				Algorithm:    AlgorithmAES256GCM,
				IsStreamable: true,
			},
			IntegrityInformation: IntegrityInformation{
				RootSignature: RootSignature{
					Algorithm: AlgorithmHS256,
				},
				SegmentHashAlgorithm: AlgorithmGMAC,
				Segments:             []Segment{},
			},
		},
	}
}

// ToJSON serializes the manifest to JSON bytes.
func (m *Manifest) ToJSON() ([]byte, error) {
	return json.Marshal(m)
}

// ToJSONPretty serializes the manifest to indented JSON bytes.
func (m *Manifest) ToJSONPretty() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// FromJSON deserializes a manifest from JSON bytes.
func FromJSON(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
