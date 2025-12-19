package manifest

// Assertion represents a verifiable statement about the TDF or its payload.
// Assertions are used for security labeling, handling instructions, and metadata.
type Assertion struct {
	// ID is a unique identifier for this assertion within the manifest.
	ID string `json:"id"`

	// Type categorizes the assertion's purpose.
	// Common values: "handling" (caveats, dissemination controls), "metadata"
	Type string `json:"type"`

	// Scope specifies what the assertion applies to.
	// Values: "tdo" (entire TDF object), "payload" (just the payload)
	Scope string `json:"scope"`

	// AppliesToState indicates if the statement applies to encrypted or unencrypted data.
	// Values: "encrypted", "unencrypted"
	AppliesToState string `json:"appliesToState,omitempty"`

	// Statement is the actual assertion content.
	Statement Statement `json:"statement"`

	// Binding is a cryptographic signature ensuring the assertion's integrity.
	Binding AssertionBinding `json:"binding"`
}

// Statement contains the assertion's content.
type Statement struct {
	// Format describes the content encoding format.
	// Values: "json-structured", "xml-structured", "base64binary", "string"
	Format string `json:"format"`

	// Schema is a URI identifying the schema for structured content.
	Schema string `json:"schema,omitempty"`

	// Value is the statement content, encoded per Format.
	// Can be a string or structured JSON object.
	Value interface{} `json:"value"`
}

// AssertionBinding ensures the assertion cannot be moved to another TDF.
type AssertionBinding struct {
	// Method is the binding method used.
	// Default is "jws" (JSON Web Signature).
	Method string `json:"method"`

	// Signature is the cryptographic signature binding this assertion.
	Signature string `json:"signature"`
}

// Assertion types
const (
	AssertionTypeHandling = "handling"
	AssertionTypeMetadata = "metadata"
)

// Assertion scopes
const (
	AssertionScopeTDO     = "tdo"
	AssertionScopePayload = "payload"
)

// Assertion states
const (
	AssertionStateEncrypted   = "encrypted"
	AssertionStateUnencrypted = "unencrypted"
)

// Statement formats
const (
	StatementFormatJSONStructured = "json-structured"
	StatementFormatXMLStructured  = "xml-structured"
	StatementFormatBase64Binary   = "base64binary"
	StatementFormatString         = "string"
)

