package manifest

// Payload describes the encrypted payload within the TDF archive.
type Payload struct {
	// Type describes how the payload is referenced.
	// Currently only "reference" is specified.
	Type string `json:"type"`

	// Reference is the location of the payload.
	// For type="reference", this is a relative path within the ZIP archive.
	// Maps to "url" in the TDF spec.
	Reference string `json:"url"`

	// Protocol designates the packaging format.
	// Values: "zip" for standard files, "zipstream" for streamed files.
	Protocol string `json:"protocol"`

	// IsEncrypted indicates whether the payload is encrypted.
	// Must be true for standard TDFs.
	IsEncrypted bool `json:"isEncrypted"`

	// MIMEType specifies the MIME type of the original, unencrypted data.
	// Defaults to "application/octet-stream" if not provided.
	MIMEType string `json:"mimeType,omitempty"`
}

