package nanotdf

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/opentdf/spec/pkg/crypto"
)

// Header errors
var (
	ErrInvalidMagicNumber = errors.New("invalid NanoTDF magic number")
	ErrInvalidVersion     = errors.New("invalid NanoTDF version")
	ErrUnsupportedECCMode = errors.New("unsupported ECC mode")
	ErrInvalidHeader      = errors.New("invalid header format")
	ErrHeaderTooShort     = errors.New("header data too short")
)

// Header represents the NanoTDF header.
// Contains all metadata needed to decrypt the payload.
type Header struct {
	// Version is the NanoTDF version (must be >= 12)
	Version uint8

	// Locator identifies the key authority (maps to KAS in TDF spec).
	// This is the Resource Locator from section 3.4.1.
	Locator ResourceLocator

	// ECCMode specifies the elliptic curve parameters
	ECCMode ECCMode

	// UseECDSABinding indicates if ECDSA is used for policy binding (vs GMAC)
	UseECDSABinding bool

	// SymmetricCipher specifies the symmetric encryption algorithm
	SymmetricCipher SymmetricCipher

	// HasSignature indicates if the NanoTDF includes a creator signature
	HasSignature bool

	// SignatureECCMode specifies the ECC mode for the signature (if HasSignature)
	SignatureECCMode ECCMode

	// Policy contains the policy information
	Policy Policy

	// EphemeralPublicKey is the sender's ephemeral public key for ECDH
	EphemeralPublicKey []byte // Compressed format
}

// ResourceLocator represents a reference to an external resource.
// Used for KAS location and remote policies.
type ResourceLocator struct {
	// Protocol is the protocol enum (HTTP, HTTPS, etc.)
	Protocol ProtocolEnum

	// IdentifierType indicates the type of identifier
	IdentifierType IdentifierType

	// Body is the resource location (e.g., hostname for HTTP/HTTPS)
	Body string

	// Identifier is optional additional identifier (e.g., key ID)
	Identifier []byte
}

// Policy represents the NanoTDF policy structure.
type Policy struct {
	// Type indicates how the policy is stored
	Type PolicyType

	// Body contains the policy data
	// For remote: ResourceLocator
	// For embedded: raw policy bytes (plaintext or encrypted)
	Body []byte

	// Binding is the cryptographic binding of the policy to the key
	// Either GMAC (8 bytes) or ECDSA signature (variable)
	Binding []byte

	// Remote is populated for PolicyTypeRemote
	Remote *ResourceLocator
}

// ParseHeader reads and parses a NanoTDF header from a reader.
func ParseHeader(r io.Reader) (*Header, error) {
	h := &Header{}

	// Read magic number + version (3 bytes)
	magic := make([]byte, MagicVersionSize)
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHeaderTooShort, err)
	}

	// Verify magic number (first 18 bits)
	if magic[0] != MagicNumberByte0 || magic[1] != MagicNumberByte1 {
		return nil, ErrInvalidMagicNumber
	}

	// Extract version from last 6 bits of magic[2]
	h.Version = magic[2] & 0x3F
	if h.Version < Version12 {
		return nil, fmt.Errorf("%w: version %d", ErrInvalidVersion, h.Version)
	}

	// Read KAS resource locator
	locator, err := parseResourceLocator(r)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KAS locator: %w", err)
	}
	h.Locator = locator

	// Read ECC and Binding Mode (1 byte)
	eccBinding := make([]byte, ECCBindingSize)
	if _, err := io.ReadFull(r, eccBinding); err != nil {
		return nil, fmt.Errorf("%w: ECC binding mode", ErrHeaderTooShort)
	}

	h.UseECDSABinding = (eccBinding[0] & 0x80) != 0
	h.ECCMode = ECCMode(eccBinding[0] & 0x07)

	// Validate ECC mode
	if _, err := crypto.CurveForMode(h.ECCMode); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedECCMode, err)
	}

	// Read Symmetric and Payload Config (1 byte)
	symConfig := make([]byte, SymmetricSize)
	if _, err := io.ReadFull(r, symConfig); err != nil {
		return nil, fmt.Errorf("%w: symmetric config", ErrHeaderTooShort)
	}

	h.HasSignature = (symConfig[0] & 0x80) != 0
	h.SignatureECCMode = ECCMode((symConfig[0] >> 4) & 0x07)
	h.SymmetricCipher = SymmetricCipher(symConfig[0] & 0x0F)

	// Read Policy
	policy, err := parsePolicy(r, h.ECCMode, h.UseECDSABinding)
	if err != nil {
		return nil, fmt.Errorf("failed to parse policy: %w", err)
	}
	h.Policy = policy

	// Read Ephemeral Public Key
	keySize := crypto.CompressedPublicKeySize(h.ECCMode)
	h.EphemeralPublicKey = make([]byte, keySize)
	if _, err := io.ReadFull(r, h.EphemeralPublicKey); err != nil {
		return nil, fmt.Errorf("%w: ephemeral key", ErrHeaderTooShort)
	}

	return h, nil
}

// parseResourceLocator parses a resource locator from a reader.
func parseResourceLocator(r io.Reader) (ResourceLocator, error) {
	var rl ResourceLocator

	// Read protocol header (1 byte)
	header := make([]byte, 1)
	if _, err := io.ReadFull(r, header); err != nil {
		return rl, err
	}

	rl.Protocol = ProtocolEnum(header[0] & 0x0F)
	rl.IdentifierType = IdentifierType((header[0] >> 4) & 0x0F)

	// Read body length (1 byte)
	lenByte := make([]byte, 1)
	if _, err := io.ReadFull(r, lenByte); err != nil {
		return rl, err
	}
	bodyLen := int(lenByte[0])

	// Read body
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return rl, err
	}
	rl.Body = string(body)

	// Read identifier if present
	idSize := rl.IdentifierType.Size()
	if idSize > 0 {
		rl.Identifier = make([]byte, idSize)
		if _, err := io.ReadFull(r, rl.Identifier); err != nil {
			return rl, err
		}
	}

	return rl, nil
}

// parsePolicy parses a policy from a reader.
func parsePolicy(r io.Reader, eccMode ECCMode, useECDSA bool) (Policy, error) {
	var p Policy

	// Read policy type (1 byte)
	typeByte := make([]byte, 1)
	if _, err := io.ReadFull(r, typeByte); err != nil {
		return p, err
	}
	p.Type = PolicyType(typeByte[0])

	switch p.Type {
	case PolicyTypeRemote:
		// Parse resource locator
		rl, err := parseResourceLocator(r)
		if err != nil {
			return p, err
		}
		p.Remote = &rl

	case PolicyTypeEmbeddedPlaintext, PolicyTypeEmbeddedEncrypted, PolicyTypeEmbeddedEncryptedPKA:
		// Read content length (2 bytes, big endian)
		lenBytes := make([]byte, 2)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return p, err
		}
		contentLen := int(binary.BigEndian.Uint16(lenBytes))

		// Read content
		p.Body = make([]byte, contentLen)
		if _, err := io.ReadFull(r, p.Body); err != nil {
			return p, err
		}

		// For PolicyTypeEmbeddedEncryptedPKA, there's additional Policy Key Access data
		// which we'd need to parse, but skip for basic implementation
	}

	// Read binding
	var bindingSize int
	if useECDSA {
		// ECDSA signature size depends on ECC mode
		bindingSize = crypto.SignatureSize(eccMode)
	} else {
		// GMAC is always 8 bytes
		bindingSize = 8
	}

	p.Binding = make([]byte, bindingSize)
	if _, err := io.ReadFull(r, p.Binding); err != nil {
		return p, err
	}

	return p, nil
}

// MarshalHeader writes the header to a byte slice.
func (h *Header) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	// Write magic number + version
	buf.WriteByte(MagicNumberByte0)
	buf.WriteByte(MagicNumberByte1)
	buf.WriteByte(MagicNumberByte2) // Version 12

	// Write KAS resource locator
	if err := writeResourceLocator(&buf, h.Locator); err != nil {
		return nil, err
	}

	// Write ECC and Binding Mode
	eccBinding := uint8(h.ECCMode) & 0x07
	if h.UseECDSABinding {
		eccBinding |= 0x80
	}
	buf.WriteByte(eccBinding)

	// Write Symmetric and Payload Config
	symConfig := uint8(h.SymmetricCipher) & 0x0F
	symConfig |= (uint8(h.SignatureECCMode) & 0x07) << 4
	if h.HasSignature {
		symConfig |= 0x80
	}
	buf.WriteByte(symConfig)

	// Write Policy
	if err := writePolicy(&buf, h.Policy, h.ECCMode, h.UseECDSABinding); err != nil {
		return nil, err
	}

	// Write Ephemeral Public Key
	buf.Write(h.EphemeralPublicKey)

	return buf.Bytes(), nil
}

// writeResourceLocator writes a resource locator to a writer.
func writeResourceLocator(w *bytes.Buffer, rl ResourceLocator) error {
	// Protocol header
	header := uint8(rl.Protocol) | (uint8(rl.IdentifierType) << 4)
	w.WriteByte(header)

	// Body length
	if len(rl.Body) > 255 {
		return errors.New("resource locator body too long")
	}
	w.WriteByte(byte(len(rl.Body)))

	// Body
	w.WriteString(rl.Body)

	// Identifier
	if len(rl.Identifier) > 0 {
		w.Write(rl.Identifier)
	}

	return nil
}

// writePolicy writes a policy to a writer.
func writePolicy(w *bytes.Buffer, p Policy, eccMode ECCMode, useECDSA bool) error {
	// Policy type
	w.WriteByte(byte(p.Type))

	switch p.Type {
	case PolicyTypeRemote:
		if p.Remote == nil {
			return errors.New("remote policy requires resource locator")
		}
		if err := writeResourceLocator(w, *p.Remote); err != nil {
			return err
		}

	case PolicyTypeEmbeddedPlaintext, PolicyTypeEmbeddedEncrypted:
		// Content length (2 bytes, big endian)
		if len(p.Body) > 65535 {
			return errors.New("policy body too long")
		}
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, uint16(len(p.Body)))
		w.Write(lenBytes)

		// Content
		w.Write(p.Body)
	}

	// Binding
	w.Write(p.Binding)

	return nil
}

// GetEphemeralPublicKey parses the ephemeral public key from the header.
func (h *Header) GetEphemeralPublicKey() (*ecdsa.PublicKey, error) {
	curve, err := crypto.CurveForMode(h.ECCMode)
	if err != nil {
		return nil, err
	}
	return crypto.UnmarshalPublicKey(curve, h.EphemeralPublicKey)
}

// Size returns the size of the header in bytes (approximate).
func (h *Header) Size() int {
	size := MagicVersionSize + ECCBindingSize + SymmetricSize

	// KAS locator: 1 (header) + 1 (len) + body + identifier
	size += 2 + len(h.Locator.Body) + h.Locator.IdentifierType.Size()

	// Policy: 1 (type) + body + binding
	size += 1
	switch h.Policy.Type {
	case PolicyTypeRemote:
		if h.Policy.Remote != nil {
			size += 2 + len(h.Policy.Remote.Body) + h.Policy.Remote.IdentifierType.Size()
		}
	default:
		size += 2 + len(h.Policy.Body)
	}
	size += len(h.Policy.Binding)

	// Ephemeral key
	size += len(h.EphemeralPublicKey)

	return size
}

// ToURL returns the full URL for the resource locator.
func (rl *ResourceLocator) ToURL() string {
	var prefix string
	switch rl.Protocol {
	case ProtocolHTTP:
		prefix = "http://"
	case ProtocolHTTPS:
		prefix = "https://"
	default:
		prefix = ""
	}
	return prefix + rl.Body
}

// NewResourceLocator creates a resource locator from a URL-like string.
// The locator identifies the key authority (maps to KAS URL in TDF spec).
func NewResourceLocator(body string, protocol ProtocolEnum) ResourceLocator {
	return ResourceLocator{
		Protocol:       protocol,
		IdentifierType: IdentifierNone,
		Body:           body,
	}
}

// NewResourceLocatorWithID creates a resource locator with a key identifier.
func NewResourceLocatorWithID(body string, protocol ProtocolEnum, keyID []byte) ResourceLocator {
	var idType IdentifierType
	switch len(keyID) {
	case 2:
		idType = Identifier2Byte
	case 8:
		idType = Identifier8Byte
	case 32:
		idType = Identifier32Byte
	default:
		idType = IdentifierNone
		keyID = nil
	}

	return ResourceLocator{
		Protocol:       protocol,
		IdentifierType: idType,
		Body:           body,
		Identifier:     keyID,
	}
}
