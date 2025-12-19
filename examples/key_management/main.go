// Example: DEK Key Management
//
// This example demonstrates:
// - Generating Data Encryption Keys (DEKs)
// - Wrapping DEKs with an authority's public key
// - Unwrapping DEKs with the authority's private key
// - Rewrapping DEKs for a different recipient
// - Splitting DEKs across multiple authorities
// - Policy binding for tamper detection
//
// Run: go run ./examples/key_management/
package main

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/opentdf/spec/pkg/crypto"
	"github.com/opentdf/spec/pkg/dek"
)

func main() {
	fmt.Println("=== DEK Key Management Example ===")

	// =====================
	// 1. Generate a DEK
	// =====================
	fmt.Println("1. Generating DEK...")
	dekBytes, err := dek.Generate()
	if err != nil {
		log.Fatalf("Failed to generate DEK: %v", err)
	}
	fmt.Printf("   ✓ DEK generated: %d bytes (256 bits)\n", len(dekBytes))
	fmt.Printf("   ✓ DEK (base64): %s...\n", base64.StdEncoding.EncodeToString(dekBytes)[:20])

	// =====================
	// 2. Wrap DEK with authority's public key
	// =====================
	fmt.Println("\n2. Wrapping DEK...")

	// Generate authority key pair (in real systems, this is the KAS/authority key)
	authorityKey, _ := crypto.GenerateRSAKeyPair(2048)

	wrappedDEK, err := dek.Wrap(dekBytes, &authorityKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to wrap DEK: %v", err)
	}
	fmt.Printf("   ✓ Wrapped DEK: %d bytes\n", len(wrappedDEK))
	fmt.Println("   ✓ DEK is now encrypted with authority's public key")

	// For storage in manifest (base64 encoded)
	wrappedB64, _ := dek.WrapToBase64(dekBytes, &authorityKey.PublicKey)
	fmt.Printf("   ✓ Base64 wrapped key: %s...\n", wrappedB64[:40])

	// =====================
	// 3. Unwrap DEK with authority's private key
	// =====================
	fmt.Println("\n3. Unwrapping DEK...")

	unwrappedDEK, err := dek.Unwrap(wrappedDEK, authorityKey)
	if err != nil {
		log.Fatalf("Failed to unwrap DEK: %v", err)
	}

	// Verify it matches original
	match := true
	for i := range dekBytes {
		if dekBytes[i] != unwrappedDEK[i] {
			match = false
			break
		}
	}
	fmt.Printf("   ✓ DEK unwrapped successfully\n")
	fmt.Printf("   ✓ Matches original: %t\n", match)

	// =====================
	// 4. Rewrap DEK for a different recipient
	// =====================
	fmt.Println("\n4. Rewrapping DEK for recipient...")

	// Generate recipient key pair (this would be the client requesting access)
	recipientKey, _ := crypto.GenerateRSAKeyPair(2048)

	// Authority rewraps the DEK: unwraps with its private key, wraps with recipient's public key
	rewrappedDEK, err := dek.Rewrap(wrappedDEK, authorityKey, &recipientKey.PublicKey)
	if err != nil {
		log.Fatalf("Failed to rewrap DEK: %v", err)
	}
	fmt.Printf("   ✓ DEK rewrapped for recipient: %d bytes\n", len(rewrappedDEK))

	// Recipient can now unwrap with their private key
	recipientDEK, err := dek.Unwrap(rewrappedDEK, recipientKey)
	if err != nil {
		log.Fatalf("Recipient failed to unwrap: %v", err)
	}

	match = true
	for i := range dekBytes {
		if dekBytes[i] != recipientDEK[i] {
			match = false
			break
		}
	}
	fmt.Printf("   ✓ Recipient unwrapped DEK successfully\n")
	fmt.Printf("   ✓ Matches original: %t\n", match)

	// =====================
	// 5. Policy Binding
	// =====================
	fmt.Println("\n5. Policy binding...")

	// Create a sample policy (base64 encoded)
	policyJSON := `{"uuid":"abc-123","body":{"dataAttributes":[{"attribute":"https://example.com/attr/level/value/secret"}],"dissem":["user@example.com"]}}`
	policyB64 := base64.StdEncoding.EncodeToString([]byte(policyJSON))

	// Calculate binding: HMAC(DEK, policy)
	bindingHash, err := dek.CalculatePolicyBinding(dekBytes, policyB64)
	if err != nil {
		log.Fatalf("Failed to calculate binding: %v", err)
	}
	fmt.Printf("   ✓ Policy binding hash: %s...\n", bindingHash[:30])

	// Verify binding (authority does this before releasing key)
	err = dek.VerifyPolicyBinding(dekBytes, policyB64, bindingHash)
	if err != nil {
		fmt.Println("   ✗ Binding verification failed!")
	} else {
		fmt.Println("   ✓ Binding verified - policy hasn't been tampered with")
	}

	// Try with tampered policy
	tamperedPolicy := base64.StdEncoding.EncodeToString([]byte(`{"uuid":"abc-123","body":{"dataAttributes":[],"dissem":["attacker@evil.com"]}}`))
	err = dek.VerifyPolicyBinding(dekBytes, tamperedPolicy, bindingHash)
	if err != nil {
		fmt.Println("   ✓ Tampered policy correctly detected!")
	}

	// =====================
	// 6. Key Splitting
	// =====================
	fmt.Println("\n6. Key splitting across multiple authorities...")

	// Split the DEK into 3 shares
	shares, err := dek.Split(dekBytes, 3)
	if err != nil {
		log.Fatalf("Failed to split DEK: %v", err)
	}
	fmt.Printf("   ✓ DEK split into %d shares\n", len(shares))

	for i, share := range shares {
		fmt.Printf("   ✓ Share %d: %s...\n", i+1, base64.StdEncoding.EncodeToString(share)[:16])
	}

	// Each share would be wrapped with a different authority's key
	authority1, _ := crypto.GenerateRSAKeyPair(2048)
	authority2, _ := crypto.GenerateRSAKeyPair(2048)
	authority3, _ := crypto.GenerateRSAKeyPair(2048)

	wrappedShare1, _ := dek.Wrap(shares[0], &authority1.PublicKey)
	wrappedShare2, _ := dek.Wrap(shares[1], &authority2.PublicKey)
	wrappedShare3, _ := dek.Wrap(shares[2], &authority3.PublicKey)

	fmt.Println("\n   Each share wrapped with different authority's key:")
	fmt.Printf("   ✓ Authority 1: %d bytes\n", len(wrappedShare1))
	fmt.Printf("   ✓ Authority 2: %d bytes\n", len(wrappedShare2))
	fmt.Printf("   ✓ Authority 3: %d bytes\n", len(wrappedShare3))

	// To decrypt: unwrap each share and combine
	unwrappedShare1, _ := dek.Unwrap(wrappedShare1, authority1)
	unwrappedShare2, _ := dek.Unwrap(wrappedShare2, authority2)
	unwrappedShare3, _ := dek.Unwrap(wrappedShare3, authority3)

	reconstructedDEK, err := dek.Combine([][]byte{unwrappedShare1, unwrappedShare2, unwrappedShare3})
	if err != nil {
		log.Fatalf("Failed to combine shares: %v", err)
	}

	match = true
	for i := range dekBytes {
		if dekBytes[i] != reconstructedDEK[i] {
			match = false
			break
		}
	}
	fmt.Printf("\n   ✓ DEK reconstructed from shares\n")
	fmt.Printf("   ✓ Matches original: %t\n", match)

	// =====================
	// 7. Split with IDs
	// =====================
	fmt.Println("\n7. Key splitting with identifiers...")

	splitShares, err := dek.SplitWithIDs(dekBytes, []string{
		"authority-us-east",
		"authority-eu-west",
		"authority-ap-south",
	})
	if err != nil {
		log.Fatalf("Failed to split with IDs: %v", err)
	}

	for _, ss := range splitShares {
		fmt.Printf("   ✓ Share '%s': %s...\n", ss.ID, base64.StdEncoding.EncodeToString(ss.Share)[:12])
	}

	fmt.Println("\n=== Example Complete ===")
}
