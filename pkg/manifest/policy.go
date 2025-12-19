package manifest

import (
	"encoding/base64"
	"encoding/json"

	"github.com/google/uuid"
)

// Policy defines the access control rules for the TDF.
// This object is JSON-stringified and Base64-encoded when stored in the manifest.
type Policy struct {
	// UUID uniquely identifies this policy instance.
	UUID string `json:"uuid"`

	// Body contains the core access control constraints.
	Body PolicyBody `json:"body"`
}

// PolicyBody contains the access control constraints.
type PolicyBody struct {
	// DataAttributes specifies the attributes required to access this data.
	// An entity must possess these attributes (according to their definitions)
	// to satisfy the ABAC requirements.
	DataAttributes []Attribute `json:"dataAttributes"`

	// Dissem is an optional dissemination list.
	// If present and non-empty, an entity must be in this list
	// in addition to satisfying DataAttributes.
	Dissem []string `json:"dissem,omitempty"`
}

// Attribute represents a data attribute in URI format.
// Format: {Namespace}/attr/{Name}/value/{Value}
type Attribute struct {
	// Attribute is the full attribute URI.
	Attribute string `json:"attribute"`
}

// NewPolicy creates a new policy with a generated UUID.
func NewPolicy() *Policy {
	return &Policy{
		UUID: uuid.New().String(),
		Body: PolicyBody{
			DataAttributes: []Attribute{},
			Dissem:         []string{},
		},
	}
}

// AddAttribute adds an attribute to the policy.
func (p *Policy) AddAttribute(attributeURI string) {
	p.Body.DataAttributes = append(p.Body.DataAttributes, Attribute{
		Attribute: attributeURI,
	})
}

// AddDissemination adds an entity to the dissemination list.
func (p *Policy) AddDissemination(entityID string) {
	p.Body.Dissem = append(p.Body.Dissem, entityID)
}

// ToBase64 encodes the policy as Base64(JSON).
// This is the format stored in the manifest's encryptionInformation.policy field.
func (p *Policy) ToBase64() (string, error) {
	jsonBytes, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}

// PolicyFromBase64 decodes a policy from Base64-encoded JSON.
func PolicyFromBase64(encoded string) (*Policy, error) {
	jsonBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	var p Policy
	if err := json.Unmarshal(jsonBytes, &p); err != nil {
		return nil, err
	}

	return &p, nil
}

