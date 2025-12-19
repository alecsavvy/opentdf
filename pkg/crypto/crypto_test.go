package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAESGCMEncryptDecrypt(t *testing.T) {
	// Generate a random key
	key := make([]byte, AESKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Generate nonce
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("failed to generate nonce: %v", err)
	}

	plaintext := []byte("Hello, OpenTDF! This is a test message.")
	additionalData := []byte("additional authenticated data")

	// Encrypt
	ciphertext, err := EncryptAESGCM(key, nonce, plaintext, additionalData)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Verify ciphertext is different from plaintext
	if bytes.Equal(ciphertext[:len(plaintext)], plaintext) {
		t.Error("ciphertext should be different from plaintext")
	}

	// Decrypt
	decrypted, err := DecryptAESGCM(key, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	// Verify
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted text doesn't match: got %q, want %q", decrypted, plaintext)
	}
}

func TestAESGCMTamperedCiphertext(t *testing.T) {
	key := make([]byte, AESKeySize)
	rand.Read(key)

	nonce, _ := GenerateNonce()
	plaintext := []byte("secret message")

	ciphertext, _ := EncryptAESGCM(key, nonce, plaintext, nil)

	// Tamper with ciphertext
	ciphertext[0] ^= 0xFF

	// Decryption should fail
	_, err := DecryptAESGCM(key, nonce, ciphertext, nil)
	if err == nil {
		t.Error("expected decryption to fail with tampered ciphertext")
	}
}

func TestSegmentEncryptorDecryptor(t *testing.T) {
	key := make([]byte, AESKeySize)
	rand.Read(key)

	segmentSize := 1024
	encryptor, err := NewSegmentEncryptor(key, segmentSize)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	// Encrypt multiple segments
	segments := [][]byte{
		[]byte("First segment of data"),
		[]byte("Second segment of data with more content"),
		[]byte("Third and final segment"),
	}

	var ciphertexts [][]byte
	var tags [][]byte

	for _, seg := range segments {
		ct, tag, err := encryptor.EncryptSegment(seg)
		if err != nil {
			t.Fatalf("segment encryption failed: %v", err)
		}
		ciphertexts = append(ciphertexts, ct)
		tags = append(tags, tag)
	}

	// Create decryptor with same key and base nonce
	decryptor, err := NewSegmentDecryptor(key, encryptor.BaseNonce())
	if err != nil {
		t.Fatalf("failed to create decryptor: %v", err)
	}

	// Decrypt and verify
	for i, ct := range ciphertexts {
		pt, err := decryptor.DecryptSegment(ct)
		if err != nil {
			t.Fatalf("segment %d decryption failed: %v", i, err)
		}
		if !bytes.Equal(pt, segments[i]) {
			t.Errorf("segment %d mismatch: got %q, want %q", i, pt, segments[i])
		}
	}
}

func TestRSAWrapUnwrap(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key pair: %v", err)
	}

	// Generate a DEK to wrap
	dek := make([]byte, AESKeySize)
	rand.Read(dek)

	// Wrap
	wrapped, err := WrapKeyRSA(dek, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	// Unwrap
	unwrapped, err := UnwrapKeyRSA(wrapped, privateKey)
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}

	// Verify
	if !bytes.Equal(unwrapped, dek) {
		t.Error("unwrapped key doesn't match original")
	}
}

func TestRSAWrongKeyFails(t *testing.T) {
	// Generate two different key pairs
	correctKey, _ := GenerateRSAKeyPair(2048)
	wrongKey, _ := GenerateRSAKeyPair(2048)

	// Generate a DEK
	dek := make([]byte, AESKeySize)
	rand.Read(dek)

	// Wrap with correct key's public key
	wrapped, err := WrapKeyRSA(dek, &correctKey.PublicKey)
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	// Attempt to unwrap with wrong private key - MUST fail
	_, err = UnwrapKeyRSA(wrapped, wrongKey)
	if err == nil {
		t.Error("SECURITY: unwrap should fail with wrong private key")
	}
}

func TestRSARewrap(t *testing.T) {
	// Generate authority key pair (like KAS)
	authorityKey, _ := GenerateRSAKeyPair(2048)

	// Generate recipient key pair (client)
	recipientKey, _ := GenerateRSAKeyPair(2048)

	// Generate DEK
	dek := make([]byte, AESKeySize)
	rand.Read(dek)

	// Wrap with authority key
	wrapped, _ := WrapKeyRSA(dek, &authorityKey.PublicKey)

	// Rewrap for recipient
	rewrapped, err := RewrapKeyRSA(wrapped, authorityKey, &recipientKey.PublicKey)
	if err != nil {
		t.Fatalf("rewrap failed: %v", err)
	}

	// Recipient unwraps
	unwrapped, err := UnwrapKeyRSA(rewrapped, recipientKey)
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}

	// Verify
	if !bytes.Equal(unwrapped, dek) {
		t.Error("rewrapped key doesn't decrypt to original DEK")
	}
}

func TestHMACSHA256(t *testing.T) {
	key := []byte("secret-key")
	message := []byte("message to authenticate")

	mac1 := HMACSHA256(key, message)
	mac2 := HMACSHA256(key, message)

	// Same input should produce same output
	if !bytes.Equal(mac1, mac2) {
		t.Error("HMAC should be deterministic")
	}

	// Different message should produce different MAC
	mac3 := HMACSHA256(key, []byte("different message"))
	if bytes.Equal(mac1, mac3) {
		t.Error("different messages should produce different MACs")
	}
}

func TestPolicyBinding(t *testing.T) {
	dek := make([]byte, AESKeySize)
	rand.Read(dek)

	policyBase64 := "eyJ1dWlkIjoiMTIzIn0=" // Base64 encoded policy

	binding := CalculatePolicyBinding(dek, policyBase64)

	// Verify should succeed with correct values
	if err := VerifyPolicyBinding(dek, policyBase64, binding); err != nil {
		t.Errorf("verification failed: %v", err)
	}

	// Verify should fail with wrong policy
	if err := VerifyPolicyBinding(dek, "wrong-policy", binding); err == nil {
		t.Error("verification should fail with wrong policy")
	}
}

func TestECCKeyGenAndCompression(t *testing.T) {
	for _, mode := range []ECCMode{ECCModeSecp256r1, ECCModeSecp384r1, ECCModeSecp521r1} {
		t.Run(modeName(mode), func(t *testing.T) {
			// Generate key pair
			privateKey, err := GenerateECCKeyPair(mode)
			if err != nil {
				t.Fatalf("key generation failed: %v", err)
			}

			// Compress public key
			compressed, err := CompressPublicKey(&privateKey.PublicKey)
			if err != nil {
				t.Fatalf("compression failed: %v", err)
			}

			// Verify size
			expectedSize := CompressedPublicKeySize(mode)
			if len(compressed) != expectedSize {
				t.Errorf("compressed key size: got %d, want %d", len(compressed), expectedSize)
			}

			// Decompress
			curve, _ := CurveForMode(mode)
			decompressed, err := DecompressPublicKey(curve, compressed)
			if err != nil {
				t.Fatalf("decompression failed: %v", err)
			}

			// Verify coordinates match
			if privateKey.PublicKey.X.Cmp(decompressed.X) != 0 ||
				privateKey.PublicKey.Y.Cmp(decompressed.Y) != 0 {
				t.Error("decompressed key doesn't match original")
			}
		})
	}
}

func TestECDH(t *testing.T) {
	// Generate two key pairs on the same curve
	aliceKey, _ := GenerateECCKeyPair(ECCModeSecp256r1)
	bobKey, _ := GenerateECCKeyPair(ECCModeSecp256r1)

	// Alice computes shared secret with Bob's public key
	aliceShared, err := ECDH(aliceKey, &bobKey.PublicKey)
	if err != nil {
		t.Fatalf("Alice ECDH failed: %v", err)
	}

	// Bob computes shared secret with Alice's public key
	bobShared, err := ECDH(bobKey, &aliceKey.PublicKey)
	if err != nil {
		t.Fatalf("Bob ECDH failed: %v", err)
	}

	// Shared secrets should match
	if !bytes.Equal(aliceShared, bobShared) {
		t.Error("ECDH shared secrets don't match")
	}
}

func TestECDSASignVerify(t *testing.T) {
	privateKey, _ := GenerateECCKeyPair(ECCModeSecp256r1)

	message := []byte("message to sign")
	hash := HashForSigning(message)

	// Sign
	signature, err := SignECDSA(privateKey, hash)
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	// Verify
	if !VerifyECDSA(&privateKey.PublicKey, hash, signature) {
		t.Error("signature verification failed")
	}

	// Tamper with signature
	signature[0] ^= 0xFF
	if VerifyECDSA(&privateKey.PublicKey, hash, signature) {
		t.Error("tampered signature should not verify")
	}
}

func TestHKDF(t *testing.T) {
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	// Derive a key
	key, err := DeriveNanoTDFKey(sharedSecret, 32)
	if err != nil {
		t.Fatalf("key derivation failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("derived key size: got %d, want 32", len(key))
	}

	// Same input should produce same output
	key2, _ := DeriveNanoTDFKey(sharedSecret, 32)
	if !bytes.Equal(key, key2) {
		t.Error("HKDF should be deterministic")
	}
}

func modeName(mode ECCMode) string {
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

