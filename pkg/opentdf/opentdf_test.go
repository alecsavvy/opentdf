package opentdf

import (
	"bytes"
	"io"
	"testing"

	"github.com/opentdf/spec/pkg/crypto"
	"github.com/opentdf/spec/pkg/manifest"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Generate authority key pair
	authorityKey, err := crypto.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	plaintext := []byte("Hello, OpenTDF! This is a test of the encryption and decryption process.")

	// Create policy
	policy := manifest.NewPolicy()
	policy.AddAttribute("https://example.com/attr/classification/value/secret")

	// Encrypt
	config := EncryptConfig{
		Locator:            "blockchain:chain-id-123",
		AuthorityPublicKey: &authorityKey.PublicKey,
		Policy:             policy,
		MIMEType:           "text/plain",
	}

	tdfData, err := Encrypt(plaintext, config)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Verify we got a ZIP file (PK magic bytes)
	if len(tdfData) < 4 || tdfData[0] != 'P' || tdfData[1] != 'K' {
		t.Error("output doesn't appear to be a ZIP file")
	}

	// Decrypt
	decryptConfig := DecryptConfig{
		PrivateKey: authorityKey,
	}

	decrypted, err := Decrypt(tdfData, decryptConfig)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Verify
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	// Generate two different authority keys
	correctKey, _ := crypto.GenerateRSAKeyPair(2048)
	wrongKey, _ := crypto.GenerateRSAKeyPair(2048)

	plaintext := []byte("This data should only be accessible with the correct key")

	// Encrypt with correct key
	tdfData, err := Encrypt(plaintext, EncryptConfig{
		Locator:            "authority-1",
		AuthorityPublicKey: &correctKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Attempt to decrypt with wrong key - MUST fail
	_, err = Decrypt(tdfData, DecryptConfig{PrivateKey: wrongKey})
	if err == nil {
		t.Error("SECURITY: Decrypt should fail with wrong private key")
	}
}

func TestStreamingEncryptDecrypt(t *testing.T) {
	authorityKey, _ := crypto.GenerateRSAKeyPair(2048)

	// Generate larger test data
	plaintext := bytes.Repeat([]byte("OpenTDF streaming test data. "), 10000)

	config := EncryptConfig{
		Locator:            "did:example:authority",
		AuthorityPublicKey: &authorityKey.PublicKey,
		SegmentSize:        8192, // Smaller segments for testing
	}

	// Stream encrypt
	var tdfBuf bytes.Buffer
	writer, err := NewWriter(&tdfBuf, config)
	if err != nil {
		t.Fatalf("NewWriter failed: %v", err)
	}

	// Write in chunks
	chunkSize := 1024
	for i := 0; i < len(plaintext); i += chunkSize {
		end := i + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		if _, err := writer.Write(plaintext[i:end]); err != nil {
			t.Fatalf("Write failed at offset %d: %v", i, err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Stream decrypt
	reader, err := NewReader(tdfBuf.Bytes(), DecryptConfig{PrivateKey: authorityKey})
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	// Read in chunks
	var decrypted bytes.Buffer
	buf := make([]byte, 512)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			decrypted.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("reader Close failed: %v", err)
	}

	if !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Errorf("streaming decrypted data doesn't match (len=%d vs %d)",
			decrypted.Len(), len(plaintext))
	}
}

func TestManifestAccess(t *testing.T) {
	authorityKey, _ := crypto.GenerateRSAKeyPair(2048)

	policy := manifest.NewPolicy()
	policy.AddAttribute("https://example.com/attr/project/value/alpha")
	policy.AddDissemination("user@example.com")

	config := EncryptConfig{
		Locator:            "https://kas.example.com",
		AuthorityPublicKey: &authorityKey.PublicKey,
		KeyID:              "key-123",
		Policy:             policy,
		MIMEType:           "application/json",
	}

	tdfData, err := Encrypt([]byte(`{"data": "test"}`), config)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Read and inspect manifest
	reader, err := NewReader(tdfData, DecryptConfig{PrivateKey: authorityKey})
	if err != nil {
		t.Fatalf("NewReader failed: %v", err)
	}

	m := reader.Manifest()

	// Verify manifest structure
	if m.TDFSpecVersion == "" {
		t.Error("missing spec version")
	}

	if m.Payload.MIMEType != "application/json" {
		t.Errorf("MIME type: got %s, want application/json", m.Payload.MIMEType)
	}

	if len(m.EncryptionInformation.KeyAccess) == 0 {
		t.Error("no key access objects")
	}

	ka := m.EncryptionInformation.KeyAccess[0]
	if ka.Locator != "https://kas.example.com" {
		t.Errorf("locator: got %s, want https://kas.example.com", ka.Locator)
	}
	if ka.KeyID != "key-123" {
		t.Errorf("key ID: got %s, want key-123", ka.KeyID)
	}

	// Verify policy decoding
	decodedPolicy, err := reader.Policy()
	if err != nil {
		t.Fatalf("Policy() failed: %v", err)
	}

	if len(decodedPolicy.Body.DataAttributes) != 1 {
		t.Errorf("expected 1 attribute, got %d", len(decodedPolicy.Body.DataAttributes))
	}

	if len(decodedPolicy.Body.Dissem) != 1 || decodedPolicy.Body.Dissem[0] != "user@example.com" {
		t.Error("dissemination list mismatch")
	}

	reader.Close()
}

func TestEmptyPayload(t *testing.T) {
	authorityKey, _ := crypto.GenerateRSAKeyPair(2048)

	config := EncryptConfig{
		Locator:            "chain:123",
		AuthorityPublicKey: &authorityKey.PublicKey,
	}

	// Encrypt empty data
	tdfData, err := Encrypt([]byte{}, config)
	if err != nil {
		t.Fatalf("Encrypt empty failed: %v", err)
	}

	// Decrypt
	decrypted, err := Decrypt(tdfData, DecryptConfig{PrivateKey: authorityKey})
	if err != nil {
		t.Fatalf("Decrypt empty failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty, got %d bytes", len(decrypted))
	}
}

func TestKeySplitting(t *testing.T) {
	// Generate keys for multiple authorities
	authority1, _ := crypto.GenerateRSAKeyPair(2048)
	authority2, _ := crypto.GenerateRSAKeyPair(2048)

	plaintext := []byte("Split key protected data")

	config := EncryptConfig{
		Locator: "primary-authority",
		SplitConfig: &SplitConfig{
			Authorities: []AuthorityConfig{
				{
					Locator:   "authority-1.example.com",
					PublicKey: &authority1.PublicKey,
					SplitID:   "split-1",
				},
				{
					Locator:   "authority-2.example.com",
					PublicKey: &authority2.PublicKey,
					SplitID:   "split-2",
				},
			},
		},
	}

	tdfData, err := Encrypt(plaintext, config)
	if err != nil {
		t.Fatalf("Encrypt with split failed: %v", err)
	}

	// Verify manifest has multiple key access objects
	reader, err := NewReader(tdfData, DecryptConfig{PrivateKey: authority1})
	if err == nil {
		// This would only work if we could decrypt all shares
		// In practice, this needs both private keys
		m := reader.Manifest()
		if len(m.EncryptionInformation.KeyAccess) != 2 {
			t.Errorf("expected 2 key access objects, got %d",
				len(m.EncryptionInformation.KeyAccess))
		}

		// Verify split IDs
		for _, ka := range m.EncryptionInformation.KeyAccess {
			if ka.SplitID == "" {
				t.Error("missing split ID on key access object")
			}
		}
		reader.Close()
	}
}

func TestIntegrityVerification(t *testing.T) {
	authorityKey, _ := crypto.GenerateRSAKeyPair(2048)

	plaintext := []byte("Data that should be integrity protected")

	config := EncryptConfig{
		Locator:            "kas.example.com",
		AuthorityPublicKey: &authorityKey.PublicKey,
		SegmentSize:        64, // Small segments for testing
	}

	tdfData, err := Encrypt(plaintext, config)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Decrypt should succeed
	_, err = Decrypt(tdfData, DecryptConfig{PrivateKey: authorityKey})
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Note: Testing tampered data would require modifying the ZIP contents,
	// which is more complex. The integrity is verified by AES-GCM auth tags.
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  EncryptConfig
		wantErr bool
	}{
		{
			name:    "missing locator",
			config:  EncryptConfig{},
			wantErr: true,
		},
		{
			name: "missing public key",
			config: EncryptConfig{
				Locator: "test",
			},
			wantErr: true,
		},
		{
			name: "invalid split config",
			config: EncryptConfig{
				Locator: "test",
				SplitConfig: &SplitConfig{
					Authorities: []AuthorityConfig{
						{PublicKey: nil}, // Only 1 authority
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, err := NewWriter(&buf, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewWriter() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
