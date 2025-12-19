package nanotdf

import (
	"bytes"
	"testing"

	"github.com/opentdf/spec/pkg/crypto"
)

func TestNanoTDFEncryptDecrypt(t *testing.T) {
	// Generate recipient key pair
	recipientKey, err := crypto.GenerateECCKeyPair(ECCModeSecp256r1)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	plaintext := []byte("Hello, NanoTDF!")

	config := Config{
		Locator:            "kas.example.com",
		LocatorProtocol:    ProtocolHTTPS,
		RecipientPublicKey: &recipientKey.PublicKey,
		ECCMode:            ECCModeSecp256r1,
		SymmetricCipher:    CipherAES256GCM128,
		PolicyType:         PolicyTypeRemote,
	}

	// Encrypt
	nanoData, err := Encrypt(plaintext, config)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify magic number
	if len(nanoData) < 3 {
		t.Fatal("output too short")
	}
	if nanoData[0] != MagicNumberByte0 || nanoData[1] != MagicNumberByte1 {
		t.Error("invalid magic number")
	}

	// Decrypt
	decrypted, err := Decrypt(nanoData, recipientKey)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestNanoTDFWrongKeyFails(t *testing.T) {
	// Generate two different ECC key pairs
	correctKey, _ := crypto.GenerateECCKeyPair(ECCModeSecp256r1)
	wrongKey, _ := crypto.GenerateECCKeyPair(ECCModeSecp256r1)

	plaintext := []byte("This NanoTDF should only be decryptable with the correct key")

	// Encrypt with correct key
	nanoData, err := Encrypt(plaintext, Config{
		Locator:            "authority",
		RecipientPublicKey: &correctKey.PublicKey,
		ECCMode:            ECCModeSecp256r1,
		SymmetricCipher:    CipherAES256GCM128,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Attempt to decrypt with wrong key - MUST fail
	_, err = Decrypt(nanoData, wrongKey)
	if err == nil {
		t.Error("SECURITY: Decrypt should fail with wrong private key")
	}
}

func TestNanoTDFWithEmbeddedPolicy(t *testing.T) {
	recipientKey, _ := crypto.GenerateECCKeyPair(ECCModeSecp256r1)

	plaintext := []byte("Data with embedded policy")
	policyData := []byte(`{"uuid":"1234","body":{}}`)

	config := Config{
		Locator:            "kas.example.com",
		RecipientPublicKey: &recipientKey.PublicKey,
		ECCMode:            ECCModeSecp256r1,
		SymmetricCipher:    CipherAES256GCM128,
		PolicyType:         PolicyTypeEmbeddedPlaintext,
		Policy:             policyData,
	}

	nanoData, err := Encrypt(plaintext, config)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(nanoData, recipientKey)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted doesn't match")
	}
}

func TestNanoTDFDifferentCurves(t *testing.T) {
	curves := []ECCMode{
		ECCModeSecp256r1,
		ECCModeSecp384r1,
		ECCModeSecp521r1,
	}

	plaintext := []byte("Testing different ECC curves")

	for _, curve := range curves {
		t.Run(curveName(curve), func(t *testing.T) {
			recipientKey, err := crypto.GenerateECCKeyPair(curve)
			if err != nil {
				t.Fatalf("key generation failed: %v", err)
			}

			config := Config{
				Locator:            "kas.example.com",
				RecipientPublicKey: &recipientKey.PublicKey,
				ECCMode:            curve,
				SymmetricCipher:    CipherAES256GCM128,
			}

			nanoData, err := Encrypt(plaintext, config)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := Decrypt(nanoData, recipientKey)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Error("decrypted doesn't match")
			}
		})
	}
}

func TestNanoTDFDifferentTagSizes(t *testing.T) {
	recipientKey, _ := crypto.GenerateECCKeyPair(ECCModeSecp256r1)
	plaintext := []byte("Testing different GCM tag sizes")

	ciphers := []SymmetricCipher{
		CipherAES256GCM64,
		CipherAES256GCM96,
		CipherAES256GCM104,
		CipherAES256GCM112,
		CipherAES256GCM120,
		CipherAES256GCM128,
	}

	for _, cipher := range ciphers {
		t.Run(cipherName(cipher), func(t *testing.T) {
			config := Config{
				Locator:            "kas.example.com",
				RecipientPublicKey: &recipientKey.PublicKey,
				ECCMode:            ECCModeSecp256r1,
				SymmetricCipher:    cipher,
			}

			nanoData, err := Encrypt(plaintext, config)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := Decrypt(nanoData, recipientKey)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, plaintext) {
				t.Error("decrypted doesn't match")
			}
		})
	}
}

func TestNanoTDFWithECDSABinding(t *testing.T) {
	recipientKey, _ := crypto.GenerateECCKeyPair(ECCModeSecp256r1)
	plaintext := []byte("Data with ECDSA policy binding")

	config := Config{
		Locator:            "kas.example.com",
		RecipientPublicKey: &recipientKey.PublicKey,
		ECCMode:            ECCModeSecp256r1,
		SymmetricCipher:    CipherAES256GCM128,
		UseECDSABinding:    true,
	}

	nanoData, err := Encrypt(plaintext, config)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(nanoData, recipientKey)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted doesn't match")
	}
}

func TestNanoTDFWithSignature(t *testing.T) {
	recipientKey, _ := crypto.GenerateECCKeyPair(ECCModeSecp256r1)
	signingKey, _ := crypto.GenerateECCKeyPair(ECCModeSecp256r1)

	plaintext := []byte("Signed NanoTDF data")

	config := Config{
		Locator:            "kas.example.com",
		RecipientPublicKey: &recipientKey.PublicKey,
		ECCMode:            ECCModeSecp256r1,
		SymmetricCipher:    CipherAES256GCM128,
		SigningKey:         signingKey,
		SignatureECCMode:   ECCModeSecp256r1,
	}

	nanoData, err := Encrypt(plaintext, config)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Signature adds to the size
	t.Logf("NanoTDF size with signature: %d bytes", len(nanoData))

	decrypted, err := Decrypt(nanoData, recipientKey)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted doesn't match")
	}
}

func TestNanoTDFHeaderParsing(t *testing.T) {
	recipientKey, _ := crypto.GenerateECCKeyPair(ECCModeSecp256r1)
	plaintext := []byte("Test data for header inspection")

	config := Config{
		Locator:            "kas.example.com",
		LocatorProtocol:    ProtocolHTTPS,
		RecipientPublicKey: &recipientKey.PublicKey,
		ECCMode:            ECCModeSecp256r1,
		SymmetricCipher:    CipherAES256GCM128,
	}

	nanoData, err := Encrypt(plaintext, config)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Parse just the header
	reader := bytes.NewReader(nanoData)
	header, err := ParseHeader(reader)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}

	// Verify header fields
	if header.Version != Version12 {
		t.Errorf("version: got %d, want %d", header.Version, Version12)
	}

	if header.Locator.Body != "kas.example.com" {
		t.Errorf("locator body: got %s, want kas.example.com", header.Locator.Body)
	}

	if header.Locator.Protocol != ProtocolHTTPS {
		t.Errorf("locator protocol: got %d, want %d", header.Locator.Protocol, ProtocolHTTPS)
	}

	if header.ECCMode != ECCModeSecp256r1 {
		t.Errorf("ECC mode: got %d, want %d", header.ECCMode, ECCModeSecp256r1)
	}

	if header.SymmetricCipher != CipherAES256GCM128 {
		t.Errorf("cipher: got %d, want %d", header.SymmetricCipher, CipherAES256GCM128)
	}
}

func TestNanoTDFEmptyPayload(t *testing.T) {
	recipientKey, _ := crypto.GenerateECCKeyPair(ECCModeSecp256r1)

	config := Config{
		Locator:            "kas.example.com",
		RecipientPublicKey: &recipientKey.PublicKey,
		ECCMode:            ECCModeSecp256r1,
		SymmetricCipher:    CipherAES256GCM128,
	}

	nanoData, err := Encrypt([]byte{}, config)
	if err != nil {
		t.Fatalf("Encrypt empty failed: %v", err)
	}

	decrypted, err := Decrypt(nanoData, recipientKey)
	if err != nil {
		t.Fatalf("Decrypt empty failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty, got %d bytes", len(decrypted))
	}
}

func TestNanoTDFMinimalSize(t *testing.T) {
	recipientKey, _ := crypto.GenerateECCKeyPair(ECCModeSecp256r1)

	config := Config{
		Locator:            "x", // Minimal locator
		RecipientPublicKey: &recipientKey.PublicKey,
		ECCMode:            ECCModeSecp256r1,
		SymmetricCipher:    CipherAES256GCM64, // Smallest tag
	}

	// Encrypt 1 byte
	nanoData, err := Encrypt([]byte("X"), config)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	t.Logf("Minimal NanoTDF size: %d bytes", len(nanoData))

	// Should be well under 200 bytes per spec
	if len(nanoData) > 200 {
		t.Errorf("minimal NanoTDF too large: %d bytes", len(nanoData))
	}
}

func TestResourceLocatorURL(t *testing.T) {
	tests := []struct {
		rl       ResourceLocator
		expected string
	}{
		{
			rl:       NewResourceLocator("kas.example.com", ProtocolHTTPS),
			expected: "https://kas.example.com",
		},
		{
			rl:       NewResourceLocator("localhost:8080", ProtocolHTTP),
			expected: "http://localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.rl.ToURL()
			if got != tt.expected {
				t.Errorf("ToURL(): got %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestNanoTDFValidation(t *testing.T) {
	recipientKey, _ := crypto.GenerateECCKeyPair(ECCModeSecp256r1)

	// Missing locator
	_, err := NewWriter(&bytes.Buffer{}, Config{
		RecipientPublicKey: &recipientKey.PublicKey,
	})
	if err == nil {
		t.Error("expected error for missing locator")
	}

	// Missing recipient key
	_, err = NewWriter(&bytes.Buffer{}, Config{
		Locator: "kas.example.com",
	})
	if err == nil {
		t.Error("expected error for missing recipient key")
	}
}

func curveName(mode ECCMode) string {
	switch mode {
	case ECCModeSecp256r1:
		return "secp256r1"
	case ECCModeSecp384r1:
		return "secp384r1"
	case ECCModeSecp521r1:
		return "secp521r1"
	default:
		return "unknown"
	}
}

func cipherName(c SymmetricCipher) string {
	switch c {
	case CipherAES256GCM64:
		return "GCM-64"
	case CipherAES256GCM96:
		return "GCM-96"
	case CipherAES256GCM104:
		return "GCM-104"
	case CipherAES256GCM112:
		return "GCM-112"
	case CipherAES256GCM120:
		return "GCM-120"
	case CipherAES256GCM128:
		return "GCM-128"
	default:
		return "unknown"
	}
}

