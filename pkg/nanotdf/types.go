// Package nanotdf provides encoding and decoding for NanoTDF binary format.
// NanoTDF is a compact binary format designed for resource-constrained environments.
// See the NanoTDF specification (schema/nanotdf/README.md) for details.
package nanotdf

import (
	"github.com/opentdf/spec/pkg/crypto"
)

// Version constants
const (
	// MagicNumber is the first 18 bits of a NanoTDF (0x4C314C shifted)
	// The bytes "L1L" represent version 12 (the first valid version)
	MagicNumberByte0 = 0x4C // 'L'
	MagicNumberByte1 = 0x31 // '1'
	MagicNumberByte2 = 0x4C // 'L'

	// Version12 is the first valid NanoTDF version
	Version12 = 12
)

// ECCMode represents the elliptic curve parameters for NanoTDF.
// Maps to the Ephemeral ECC Params Enum in spec section 3.3.1.3.2.
type ECCMode = crypto.ECCMode

// Re-export ECC modes from crypto package
const (
	ECCModeSecp256r1 = crypto.ECCModeSecp256r1
	ECCModeSecp384r1 = crypto.ECCModeSecp384r1
	ECCModeSecp521r1 = crypto.ECCModeSecp521r1
	ECCModeSecp256k1 = crypto.ECCModeSecp256k1
)

// SymmetricCipher represents the symmetric encryption algorithm.
// Maps to Symmetric Cipher Enum in spec section 3.3.1.4.3.
type SymmetricCipher uint8

const (
	// CipherAES256GCM64 uses AES-256-GCM with 64-bit (8 byte) tag
	CipherAES256GCM64 SymmetricCipher = 0x00
	// CipherAES256GCM96 uses AES-256-GCM with 96-bit (12 byte) tag
	CipherAES256GCM96 SymmetricCipher = 0x01
	// CipherAES256GCM104 uses AES-256-GCM with 104-bit (13 byte) tag
	CipherAES256GCM104 SymmetricCipher = 0x02
	// CipherAES256GCM112 uses AES-256-GCM with 112-bit (14 byte) tag
	CipherAES256GCM112 SymmetricCipher = 0x03
	// CipherAES256GCM120 uses AES-256-GCM with 120-bit (15 byte) tag
	CipherAES256GCM120 SymmetricCipher = 0x04
	// CipherAES256GCM128 uses AES-256-GCM with 128-bit (16 byte) tag
	CipherAES256GCM128 SymmetricCipher = 0x05
)

// TagSize returns the authentication tag size in bytes for a cipher.
func (c SymmetricCipher) TagSize() int {
	switch c {
	case CipherAES256GCM64:
		return 8
	case CipherAES256GCM96:
		return 12
	case CipherAES256GCM104:
		return 13
	case CipherAES256GCM112:
		return 14
	case CipherAES256GCM120:
		return 15
	case CipherAES256GCM128:
		return 16
	default:
		return 16
	}
}

// ProtocolEnum represents the protocol for resource locators.
// Maps to Protocol Enum in spec section 3.4.1.1.
type ProtocolEnum uint8

const (
	ProtocolHTTP  ProtocolEnum = 0x00
	ProtocolHTTPS ProtocolEnum = 0x01
	// 0x02-0x0E are unreserved
	ProtocolSharedResourceDirectory ProtocolEnum = 0x0F
)

// IdentifierType represents the type of identifier in a resource locator.
type IdentifierType uint8

const (
	IdentifierNone   IdentifierType = 0x00
	Identifier2Byte  IdentifierType = 0x01
	Identifier8Byte  IdentifierType = 0x02
	Identifier32Byte IdentifierType = 0x03
)

// IdentifierSize returns the size in bytes for an identifier type.
func (t IdentifierType) Size() int {
	switch t {
	case IdentifierNone:
		return 0
	case Identifier2Byte:
		return 2
	case Identifier8Byte:
		return 8
	case Identifier32Byte:
		return 32
	default:
		return 0
	}
}

// PolicyType represents the type of policy in NanoTDF.
// Maps to Policy Type Enum in spec section 3.4.2.1.
type PolicyType uint8

const (
	PolicyTypeRemote             PolicyType = 0x00
	PolicyTypeEmbeddedPlaintext  PolicyType = 0x01
	PolicyTypeEmbeddedEncrypted  PolicyType = 0x02
	PolicyTypeEmbeddedEncryptedPKA PolicyType = 0x03 // With Policy Key Access
)

// Header sizes
const (
	MagicVersionSize = 3
	ECCBindingSize   = 1
	SymmetricSize    = 1
	PayloadLengthSize = 3
	NanoTDFIVSize    = 3 // NanoTDF uses 3-byte IV
)

