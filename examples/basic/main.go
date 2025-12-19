// Example: Basic OpenTDF Encryption and Decryption
//
// This example demonstrates:
// - Generating an RSA key pair (authority key)
// - Creating a policy with attributes
// - Encrypting plaintext data to TDF format
// - Decrypting TDF data back to plaintext
//
// Run: go run ./examples/basic/
package main

import (
	"fmt"
	"log"

	"github.com/opentdf/spec/pkg/crypto"
	"github.com/opentdf/spec/pkg/manifest"
	"github.com/opentdf/spec/pkg/opentdf"
)

func main() {
	fmt.Println("=== OpenTDF Basic Encryption/Decryption Example ===")

	// Step 1: Generate an authority key pair
	// In a real system, this would be the key managed by your key authority
	// (traditionally called KAS - Key Access Server)
	fmt.Println("1. Generating RSA key pair for the authority...")
	authorityKey, err := crypto.GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}
	fmt.Println("   ✓ RSA-2048 key pair generated")

	// Step 2: Create a policy
	// Policies define who can access the encrypted data
	fmt.Println("\n2. Creating access policy...")
	policy := manifest.NewPolicy()

	// Add attributes that define access requirements
	policy.AddAttribute("https://example.com/attr/classification/value/confidential")
	policy.AddAttribute("https://example.com/attr/department/value/engineering")

	// Add specific entities to the dissemination list
	policy.AddDissemination("alice@example.com")
	policy.AddDissemination("bob@example.com")

	fmt.Printf("   ✓ Policy created with UUID: %s\n", policy.UUID)
	fmt.Printf("   ✓ Attributes: %d\n", len(policy.Body.DataAttributes))
	fmt.Printf("   ✓ Dissemination list: %v\n", policy.Body.Dissem)

	// Step 3: Encrypt data
	fmt.Println("\n3. Encrypting data...")
	plaintext := []byte("This is sensitive data that needs protection. " +
		"Only authorized users with the correct attributes should be able to read this.")

	config := opentdf.EncryptConfig{
		// Locator identifies the key authority - can be a URL, chain ID, DID, etc.
		Locator:            "https://kas.example.com",
		AuthorityPublicKey: &authorityKey.PublicKey,
		KeyID:              "key-2024-001", // Optional key identifier
		Policy:             policy,
		MIMEType:           "text/plain",
	}

	tdfData, err := opentdf.Encrypt(plaintext, config)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("   ✓ Plaintext size: %d bytes\n", len(plaintext))
	fmt.Printf("   ✓ TDF size: %d bytes (ZIP archive)\n", len(tdfData))
	fmt.Printf("   ✓ Overhead: %.1f%%\n", float64(len(tdfData)-len(plaintext))/float64(len(plaintext))*100)

	// Step 4: Decrypt data
	// In a real system, the authority would first verify the requester's attributes
	// and rewrap the DEK for the authorized client
	fmt.Println("\n4. Decrypting data...")

	decryptConfig := opentdf.DecryptConfig{
		PrivateKey: authorityKey,
	}

	decrypted, err := opentdf.Decrypt(tdfData, decryptConfig)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("   ✓ Decrypted size: %d bytes\n", len(decrypted))
	fmt.Printf("   ✓ Content matches: %t\n", string(decrypted) == string(plaintext))

	// Step 5: Inspect the manifest
	fmt.Println("\n5. Inspecting TDF manifest...")
	reader, err := opentdf.NewReader(tdfData, decryptConfig)
	if err != nil {
		log.Fatalf("Failed to create reader: %v", err)
	}

	m := reader.Manifest()
	fmt.Printf("   ✓ TDF Spec Version: %s\n", m.TDFSpecVersion)
	fmt.Printf("   ✓ Payload MIME Type: %s\n", m.Payload.MIMEType)
	fmt.Printf("   ✓ Encryption Algorithm: %s\n", m.EncryptionInformation.Method.Algorithm)
	fmt.Printf("   ✓ Key Access Objects: %d\n", len(m.EncryptionInformation.KeyAccess))

	if len(m.EncryptionInformation.KeyAccess) > 0 {
		ka := m.EncryptionInformation.KeyAccess[0]
		fmt.Printf("   ✓ Authority Locator: %s\n", ka.Locator)
		fmt.Printf("   ✓ Key ID: %s\n", ka.KeyID)
	}

	reader.Close()

	fmt.Println("\n=== Example Complete ===")
}
