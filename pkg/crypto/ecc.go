package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// ECCMode represents the elliptic curve parameters used in NanoTDF.
// Maps to the Ephemeral ECC Params Enum in the NanoTDF spec (section 3.3.1.3.2).
type ECCMode uint8

const (
	// ECCModeSecp256r1 is NIST P-256 curve
	ECCModeSecp256r1 ECCMode = 0x00
	// ECCModeSecp384r1 is NIST P-384 curve
	ECCModeSecp384r1 ECCMode = 0x01
	// ECCModeSecp521r1 is NIST P-521 curve
	ECCModeSecp521r1 ECCMode = 0x02
	// ECCModeSecp256k1 is the Bitcoin/Ethereum curve
	ECCModeSecp256k1 ECCMode = 0x03
)

var (
	ErrUnsupportedCurve    = errors.New("unsupported elliptic curve")
	ErrInvalidPublicKey    = errors.New("invalid public key")
	ErrInvalidCompressedKey = errors.New("invalid compressed public key format")
)

// CurveForMode returns the elliptic.Curve for a given ECCMode.
func CurveForMode(mode ECCMode) (elliptic.Curve, error) {
	switch mode {
	case ECCModeSecp256r1:
		return elliptic.P256(), nil
	case ECCModeSecp384r1:
		return elliptic.P384(), nil
	case ECCModeSecp521r1:
		return elliptic.P521(), nil
	case ECCModeSecp256k1:
		// Go's standard library doesn't include secp256k1
		// For full support, would need to use a library like btcec
		// For now, return an error
		return nil, fmt.Errorf("%w: secp256k1 not available in standard library", ErrUnsupportedCurve)
	default:
		return nil, ErrUnsupportedCurve
	}
}

// CompressedPublicKeySize returns the size in bytes of a compressed public key for the given mode.
func CompressedPublicKeySize(mode ECCMode) int {
	switch mode {
	case ECCModeSecp256r1, ECCModeSecp256k1:
		return 33 // 1 byte prefix + 32 bytes X coordinate
	case ECCModeSecp384r1:
		return 49 // 1 byte prefix + 48 bytes X coordinate
	case ECCModeSecp521r1:
		return 67 // 1 byte prefix + 66 bytes X coordinate
	default:
		return 0
	}
}

// UncompressedPublicKeySize returns the size in bytes of an uncompressed public key for the given mode.
func UncompressedPublicKeySize(mode ECCMode) int {
	switch mode {
	case ECCModeSecp256r1, ECCModeSecp256k1:
		return 65 // 1 byte prefix + 32 bytes X + 32 bytes Y
	case ECCModeSecp384r1:
		return 97 // 1 byte prefix + 48 bytes X + 48 bytes Y
	case ECCModeSecp521r1:
		return 133 // 1 byte prefix + 66 bytes X + 66 bytes Y
	default:
		return 0
	}
}

// SignatureSize returns the size in bytes of an ECDSA signature for the given mode.
// Signature is r || s, each component padded to the curve's byte size.
func SignatureSize(mode ECCMode) int {
	switch mode {
	case ECCModeSecp256r1, ECCModeSecp256k1:
		return 64 // 32 bytes r + 32 bytes s
	case ECCModeSecp384r1:
		return 96 // 48 bytes r + 48 bytes s
	case ECCModeSecp521r1:
		return 132 // 66 bytes r + 66 bytes s
	default:
		return 0
	}
}

// GenerateECCKeyPair generates a new ECDSA key pair for the given curve mode.
func GenerateECCKeyPair(mode ECCMode) (*ecdsa.PrivateKey, error) {
	curve, err := CurveForMode(mode)
	if err != nil {
		return nil, err
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECC key pair: %w", err)
	}

	return privateKey, nil
}

// CompressPublicKey compresses an ECDSA public key to X9.62 compressed format.
// Format: 0x02 or 0x03 prefix (depending on Y parity) + X coordinate
func CompressPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, ErrInvalidPublicKey
	}

	curve := pub.Curve
	byteLen := (curve.Params().BitSize + 7) / 8

	// Determine prefix based on Y coordinate parity
	prefix := byte(0x02)
	if pub.Y.Bit(0) == 1 {
		prefix = 0x03
	}

	// Pad X coordinate to full byte length
	xBytes := pub.X.Bytes()
	compressed := make([]byte, 1+byteLen)
	compressed[0] = prefix
	copy(compressed[1+byteLen-len(xBytes):], xBytes)

	return compressed, nil
}

// DecompressPublicKey decompresses an X9.62 compressed public key.
func DecompressPublicKey(curve elliptic.Curve, compressed []byte) (*ecdsa.PublicKey, error) {
	params := curve.Params()
	byteLen := (params.BitSize + 7) / 8

	if len(compressed) != 1+byteLen {
		return nil, ErrInvalidCompressedKey
	}

	prefix := compressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, ErrInvalidCompressedKey
	}

	x := new(big.Int).SetBytes(compressed[1:])

	// Calculate y^2 = x^3 - 3x + b (mod p) for NIST curves
	// y^2 = x^3 + ax + b
	y := decompressY(curve, x, prefix == 0x03)
	if y == nil {
		return nil, ErrInvalidCompressedKey
	}

	// Verify the point is on the curve
	if !curve.IsOnCurve(x, y) {
		return nil, ErrInvalidCompressedKey
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// decompressY calculates the Y coordinate from X for a point on the curve.
func decompressY(curve elliptic.Curve, x *big.Int, yOdd bool) *big.Int {
	params := curve.Params()
	p := params.P

	// y^2 = x^3 + ax + b
	// For NIST curves, a = -3
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)

	// a*x where a = -3 for NIST curves
	ax := new(big.Int).Mul(x, big.NewInt(-3))
	ax.Mod(ax, p)

	// x^3 + ax + b
	y2 := new(big.Int).Add(x3, ax)
	y2.Add(y2, params.B)
	y2.Mod(y2, p)

	// Calculate square root using Tonelli-Shanks or modular exponentiation
	// For p ≡ 3 (mod 4), y = y2^((p+1)/4) mod p
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))

	y := new(big.Int).Exp(y2, exp, p)

	// Check if we need the other root
	if y.Bit(0) == 1 != yOdd {
		y.Sub(p, y)
	}

	// Verify
	check := new(big.Int).Mul(y, y)
	check.Mod(check, p)
	if check.Cmp(y2) != 0 {
		return nil
	}

	return y
}

// MarshalPublicKeyUncompressed marshals a public key to uncompressed format.
// Format: 0x04 + X + Y
func MarshalPublicKeyUncompressed(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

// UnmarshalPublicKey unmarshals a public key from either compressed or uncompressed format.
func UnmarshalPublicKey(curve elliptic.Curve, data []byte) (*ecdsa.PublicKey, error) {
	if len(data) == 0 {
		return nil, ErrInvalidPublicKey
	}

	switch data[0] {
	case 0x04:
		// Uncompressed format
		x, y := elliptic.Unmarshal(curve, data)
		if x == nil {
			return nil, ErrInvalidPublicKey
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case 0x02, 0x03:
		// Compressed format
		return DecompressPublicKey(curve, data)
	default:
		return nil, ErrInvalidPublicKey
	}
}

// ECDH performs Elliptic Curve Diffie-Hellman key exchange.
// Returns the shared secret (X coordinate of the resulting point).
func ECDH(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	if privateKey == nil || publicKey == nil {
		return nil, ErrInvalidPublicKey
	}

	// Ensure both keys use the same curve
	if privateKey.Curve != publicKey.Curve {
		return nil, errors.New("curve mismatch between private and public key")
	}

	// Perform scalar multiplication: shared = privateKey.D * publicKey
	x, _ := privateKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	if x == nil {
		return nil, errors.New("ECDH computation failed")
	}

	// Return X coordinate as the shared secret
	byteLen := (privateKey.Curve.Params().BitSize + 7) / 8
	sharedSecret := make([]byte, byteLen)
	xBytes := x.Bytes()
	copy(sharedSecret[byteLen-len(xBytes):], xBytes)

	return sharedSecret, nil
}

// SignECDSA signs a message hash using ECDSA.
// Returns the signature as r || s, each padded to the curve's byte size.
func SignECDSA(privateKey *ecdsa.PrivateKey, hash []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	byteLen := (privateKey.Curve.Params().BitSize + 7) / 8

	sig := make([]byte, byteLen*2)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[byteLen-len(rBytes):byteLen], rBytes)
	copy(sig[byteLen*2-len(sBytes):], sBytes)

	return sig, nil
}

// VerifyECDSA verifies an ECDSA signature.
// The signature should be r || s format.
func VerifyECDSA(publicKey *ecdsa.PublicKey, hash, signature []byte) bool {
	byteLen := (publicKey.Curve.Params().BitSize + 7) / 8

	if len(signature) != byteLen*2 {
		return false
	}

	r := new(big.Int).SetBytes(signature[:byteLen])
	s := new(big.Int).SetBytes(signature[byteLen:])

	return ecdsa.Verify(publicKey, hash, r, s)
}

// HashForSigning computes SHA-256 hash of data for ECDSA signing.
func HashForSigning(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

