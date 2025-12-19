package dek

import (
	"bytes"
	"testing"

	"github.com/opentdf/spec/pkg/crypto"
)

func TestGenerate(t *testing.T) {
	dek1, err := Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(dek1) != DEKSize {
		t.Errorf("DEK size: got %d, want %d", len(dek1), DEKSize)
	}

	// Generate another DEK - should be different
	dek2, _ := Generate()
	if bytes.Equal(dek1, dek2) {
		t.Error("consecutive DEKs should be different")
	}
}

func TestWrapUnwrap(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := crypto.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Generate DEK
	dek, _ := Generate()

	// Wrap
	wrapped, err := Wrap(dek, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Wrap failed: %v", err)
	}

	// Wrapped should be different from original
	if bytes.Equal(wrapped, dek) {
		t.Error("wrapped key should be different from original")
	}

	// Unwrap
	unwrapped, err := Unwrap(wrapped, privateKey)
	if err != nil {
		t.Fatalf("Unwrap failed: %v", err)
	}

	// Should match original
	if !bytes.Equal(unwrapped, dek) {
		t.Error("unwrapped key doesn't match original")
	}
}

func TestUnwrapWithWrongKeyFails(t *testing.T) {
	// Generate two different key pairs
	correctKey, _ := crypto.GenerateRSAKeyPair(2048)
	wrongKey, _ := crypto.GenerateRSAKeyPair(2048)

	// Generate and wrap DEK with correct key
	dek, _ := Generate()
	wrapped, _ := Wrap(dek, &correctKey.PublicKey)

	// Attempt to unwrap with wrong key - MUST fail
	_, err := Unwrap(wrapped, wrongKey)
	if err == nil {
		t.Error("SECURITY: Unwrap should fail with wrong private key")
	}
}

func TestWrapUnwrapBase64(t *testing.T) {
	privateKey, _ := crypto.GenerateRSAKeyPair(2048)
	dek, _ := Generate()

	// Wrap to Base64
	wrappedB64, err := WrapToBase64(dek, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("WrapToBase64 failed: %v", err)
	}

	// Should be valid Base64
	if len(wrappedB64) == 0 {
		t.Error("wrapped Base64 is empty")
	}

	// Unwrap from Base64
	unwrapped, err := UnwrapFromBase64(wrappedB64, privateKey)
	if err != nil {
		t.Fatalf("UnwrapFromBase64 failed: %v", err)
	}

	if !bytes.Equal(unwrapped, dek) {
		t.Error("unwrapped key doesn't match original")
	}
}

func TestRewrap(t *testing.T) {
	// Authority key (like KAS)
	authorityKey, _ := crypto.GenerateRSAKeyPair(2048)

	// Recipient key (client)
	recipientKey, _ := crypto.GenerateRSAKeyPair(2048)

	// Generate and wrap DEK
	dek, _ := Generate()
	wrapped, _ := Wrap(dek, &authorityKey.PublicKey)

	// Rewrap for recipient
	rewrapped, err := Rewrap(wrapped, authorityKey, &recipientKey.PublicKey)
	if err != nil {
		t.Fatalf("Rewrap failed: %v", err)
	}

	// Recipient unwraps
	unwrapped, err := Unwrap(rewrapped, recipientKey)
	if err != nil {
		t.Fatalf("recipient Unwrap failed: %v", err)
	}

	// Should match original DEK
	if !bytes.Equal(unwrapped, dek) {
		t.Error("rewrapped DEK doesn't decrypt to original")
	}
}

func TestRewrapWithPolicyVerification(t *testing.T) {
	authorityKey, _ := crypto.GenerateRSAKeyPair(2048)
	recipientKey, _ := crypto.GenerateRSAKeyPair(2048)

	dek, _ := Generate()
	policyB64 := "eyJ1dWlkIjoiMTIzNCIsImJvZHkiOnt9fQ==" // Sample policy

	// Wrap DEK
	wrapped, _ := Wrap(dek, &authorityKey.PublicKey)

	// Calculate binding
	bindingHash, _ := CalculatePolicyBinding(dek, policyB64)

	// Rewrap with policy verification
	rewrapped, err := RewrapWithPolicyVerification(
		wrapped, policyB64, bindingHash,
		authorityKey, &recipientKey.PublicKey,
	)
	if err != nil {
		t.Fatalf("RewrapWithPolicyVerification failed: %v", err)
	}

	// Recipient unwraps
	unwrapped, _ := Unwrap(rewrapped, recipientKey)
	if !bytes.Equal(unwrapped, dek) {
		t.Error("rewrapped DEK doesn't match original")
	}
}

func TestRewrapWithPolicyVerificationFails(t *testing.T) {
	authorityKey, _ := crypto.GenerateRSAKeyPair(2048)
	recipientKey, _ := crypto.GenerateRSAKeyPair(2048)

	dek, _ := Generate()
	policyB64 := "eyJ1dWlkIjoiMTIzNCJ9"
	wrongPolicy := "eyJ1dWlkIjoiOTk5OSJ9"

	wrapped, _ := Wrap(dek, &authorityKey.PublicKey)
	bindingHash, _ := CalculatePolicyBinding(dek, policyB64)

	// Try to rewrap with wrong policy
	_, err := RewrapWithPolicyVerification(
		wrapped, wrongPolicy, bindingHash,
		authorityKey, &recipientKey.PublicKey,
	)
	if err == nil {
		t.Error("expected error with wrong policy")
	}
}

func TestSplitAndCombine(t *testing.T) {
	dek, _ := Generate()

	// Split into 3 shares
	shares, err := Split(dek, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if len(shares) != 3 {
		t.Errorf("expected 3 shares, got %d", len(shares))
	}

	// Each share should be DEK-sized
	for i, share := range shares {
		if len(share) != DEKSize {
			t.Errorf("share %d size: got %d, want %d", i, len(share), DEKSize)
		}
	}

	// Combine shares
	reconstructed, err := Combine(shares)
	if err != nil {
		t.Fatalf("Combine failed: %v", err)
	}

	// Should match original
	if !bytes.Equal(reconstructed, dek) {
		t.Error("reconstructed DEK doesn't match original")
	}
}

func TestSplitWithIDs(t *testing.T) {
	dek, _ := Generate()

	ids := []string{"share-1", "share-2", "share-3"}
	splitShares, err := SplitWithIDs(dek, ids)
	if err != nil {
		t.Fatalf("SplitWithIDs failed: %v", err)
	}

	// Verify IDs
	for i, ss := range splitShares {
		if ss.ID != ids[i] {
			t.Errorf("share %d ID: got %s, want %s", i, ss.ID, ids[i])
		}
	}

	// Combine
	reconstructed, err := CombineFromSplitShares(splitShares)
	if err != nil {
		t.Fatalf("CombineFromSplitShares failed: %v", err)
	}

	if !bytes.Equal(reconstructed, dek) {
		t.Error("reconstructed DEK doesn't match original")
	}
}

func TestSplitMinimum(t *testing.T) {
	dek, _ := Generate()

	// Should fail with less than 2 shares
	_, err := Split(dek, 1)
	if err == nil {
		t.Error("expected error with 1 share")
	}

	_, err = Split(dek, 0)
	if err == nil {
		t.Error("expected error with 0 shares")
	}
}

func TestPolicyBinding(t *testing.T) {
	dek, _ := Generate()
	policyB64 := "eyJ1dWlkIjoiYWJjZCJ9"

	// Calculate binding
	hash, err := CalculatePolicyBinding(dek, policyB64)
	if err != nil {
		t.Fatalf("CalculatePolicyBinding failed: %v", err)
	}

	// Verify should succeed
	if err := VerifyPolicyBinding(dek, policyB64, hash); err != nil {
		t.Errorf("VerifyPolicyBinding failed: %v", err)
	}

	// Verify should fail with wrong policy
	if err := VerifyPolicyBinding(dek, "wrong", hash); err == nil {
		t.Error("expected error with wrong policy")
	}

	// Verify should fail with wrong DEK
	wrongDEK, _ := Generate()
	if err := VerifyPolicyBinding(wrongDEK, policyB64, hash); err == nil {
		t.Error("expected error with wrong DEK")
	}
}
