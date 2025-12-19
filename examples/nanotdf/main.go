// Example: NanoTDF Compact Format
//
// This example demonstrates:
// - NanoTDF encryption using ECC (Elliptic Curve Cryptography)
// - Different ECC curves (secp256r1, secp384r1, secp521r1)
// - Variable GCM tag sizes
// - ECDSA policy binding
// - Creator signatures
//
// NanoTDF is designed for resource-constrained environments with minimal overhead.
//
// Run: go run ./examples/nanotdf/
package main

import (
	"fmt"
	"log"

	"github.com/opentdf/spec/pkg/crypto"
	"github.com/opentdf/spec/pkg/nanotdf"
)

func main() {
	fmt.Println("=== NanoTDF Compact Format Example ===")

	// =====================
	// 1. Basic NanoTDF
	// =====================
	fmt.Println("1. Basic NanoTDF encryption...")

	// Generate ECC key pair (recipient/authority key)
	recipientKey, err := crypto.GenerateECCKeyPair(nanotdf.ECCModeSecp256r1)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}
	fmt.Println("   ✓ Generated secp256r1 key pair")

	plaintext := []byte("Hello, NanoTDF! This is a compact encrypted message.")

	config := nanotdf.Config{
		// Locator can be URL, chain ID, DID, etc.
		Locator:            "kas.example.com",
		LocatorProtocol:    nanotdf.ProtocolHTTPS,
		RecipientPublicKey: &recipientKey.PublicKey,
		ECCMode:            nanotdf.ECCModeSecp256r1,
		SymmetricCipher:    nanotdf.CipherAES256GCM128,
	}

	nanoData, err := nanotdf.Encrypt(plaintext, config)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("   ✓ Plaintext: %d bytes\n", len(plaintext))
	fmt.Printf("   ✓ NanoTDF: %d bytes\n", len(nanoData))
	fmt.Printf("   ✓ Overhead: %d bytes (%.1f%%)\n",
		len(nanoData)-len(plaintext),
		float64(len(nanoData)-len(plaintext))/float64(len(plaintext))*100)

	// Decrypt
	decrypted, err := nanotdf.Decrypt(nanoData, recipientKey)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("   ✓ Decrypted: %s\n", string(decrypted))

	// =====================
	// 2. Different ECC Curves
	// =====================
	fmt.Println("\n2. Comparing ECC curves...")

	curves := []struct {
		mode nanotdf.ECCMode
		name string
	}{
		{nanotdf.ECCModeSecp256r1, "secp256r1 (P-256)"},
		{nanotdf.ECCModeSecp384r1, "secp384r1 (P-384)"},
		{nanotdf.ECCModeSecp521r1, "secp521r1 (P-521)"},
	}

	testMessage := []byte("Testing different curves")

	for _, curve := range curves {
		key, _ := crypto.GenerateECCKeyPair(curve.mode)
		cfg := nanotdf.Config{
			Locator:            "authority",
			RecipientPublicKey: &key.PublicKey,
			ECCMode:            curve.mode,
			SymmetricCipher:    nanotdf.CipherAES256GCM128,
		}

		data, _ := nanotdf.Encrypt(testMessage, cfg)
		fmt.Printf("   ✓ %s: %d bytes\n", curve.name, len(data))
	}

	// =====================
	// 3. Different Tag Sizes
	// =====================
	fmt.Println("\n3. Comparing GCM tag sizes...")

	ciphers := []struct {
		cipher nanotdf.SymmetricCipher
		name   string
	}{
		{nanotdf.CipherAES256GCM64, "64-bit tag"},
		{nanotdf.CipherAES256GCM96, "96-bit tag"},
		{nanotdf.CipherAES256GCM128, "128-bit tag"},
	}

	for _, c := range ciphers {
		cfg := nanotdf.Config{
			Locator:            "authority",
			RecipientPublicKey: &recipientKey.PublicKey,
			ECCMode:            nanotdf.ECCModeSecp256r1,
			SymmetricCipher:    c.cipher,
		}

		data, _ := nanotdf.Encrypt(testMessage, cfg)
		fmt.Printf("   ✓ AES-256-GCM %s: %d bytes\n", c.name, len(data))
	}

	// =====================
	// 4. ECDSA Policy Binding
	// =====================
	fmt.Println("\n4. ECDSA policy binding...")

	configECDSA := nanotdf.Config{
		Locator:            "kas.example.com",
		RecipientPublicKey: &recipientKey.PublicKey,
		ECCMode:            nanotdf.ECCModeSecp256r1,
		SymmetricCipher:    nanotdf.CipherAES256GCM128,
		UseECDSABinding:    true, // Use ECDSA instead of GMAC for binding
	}

	nanoECDSA, err := nanotdf.Encrypt(plaintext, configECDSA)
	if err != nil {
		log.Fatalf("ECDSA binding encryption failed: %v", err)
	}

	fmt.Printf("   ✓ With ECDSA binding: %d bytes\n", len(nanoECDSA))
	fmt.Printf("   ✓ Difference from GMAC: %+d bytes\n", len(nanoECDSA)-len(nanoData))

	decryptedECDSA, err := nanotdf.Decrypt(nanoECDSA, recipientKey)
	if err != nil {
		log.Fatalf("ECDSA binding decryption failed: %v", err)
	}
	fmt.Printf("   ✓ Decrypted successfully: %t\n", string(decryptedECDSA) == string(plaintext))

	// =====================
	// 5. Creator Signature
	// =====================
	fmt.Println("\n5. Creator signature...")

	// Generate a separate signing key for the creator
	signingKey, _ := crypto.GenerateECCKeyPair(nanotdf.ECCModeSecp256r1)

	configSigned := nanotdf.Config{
		Locator:            "kas.example.com",
		RecipientPublicKey: &recipientKey.PublicKey,
		ECCMode:            nanotdf.ECCModeSecp256r1,
		SymmetricCipher:    nanotdf.CipherAES256GCM128,
		SigningKey:         signingKey,
		SignatureECCMode:   nanotdf.ECCModeSecp256r1,
	}

	nanoSigned, err := nanotdf.Encrypt(plaintext, configSigned)
	if err != nil {
		log.Fatalf("Signed encryption failed: %v", err)
	}

	fmt.Printf("   ✓ With creator signature: %d bytes\n", len(nanoSigned))
	fmt.Printf("   ✓ Signature overhead: %+d bytes\n", len(nanoSigned)-len(nanoData))

	decryptedSigned, err := nanotdf.Decrypt(nanoSigned, recipientKey)
	if err != nil {
		log.Fatalf("Signed decryption failed: %v", err)
	}
	fmt.Printf("   ✓ Signature verified, decrypted: %t\n", string(decryptedSigned) == string(plaintext))

	// =====================
	// 6. Embedded Policy
	// =====================
	fmt.Println("\n6. Embedded policy...")

	policyData := []byte(`{"uuid":"nano-policy-123","body":{"dataAttributes":[{"attribute":"https://example.com/attr/level/value/public"}]}}`)

	configPolicy := nanotdf.Config{
		Locator:            "kas.example.com",
		RecipientPublicKey: &recipientKey.PublicKey,
		ECCMode:            nanotdf.ECCModeSecp256r1,
		SymmetricCipher:    nanotdf.CipherAES256GCM128,
		PolicyType:         nanotdf.PolicyTypeEmbeddedPlaintext,
		Policy:             policyData,
	}

	nanoPolicy, err := nanotdf.Encrypt(plaintext, configPolicy)
	if err != nil {
		log.Fatalf("Policy encryption failed: %v", err)
	}

	fmt.Printf("   ✓ With embedded policy: %d bytes\n", len(nanoPolicy))
	fmt.Printf("   ✓ Policy size: %d bytes\n", len(policyData))

	// =====================
	// 7. Minimal Size Demo
	// =====================
	fmt.Println("\n7. Minimal NanoTDF size...")

	minimalConfig := nanotdf.Config{
		Locator:            "x", // Minimal locator
		RecipientPublicKey: &recipientKey.PublicKey,
		ECCMode:            nanotdf.ECCModeSecp256r1,
		SymmetricCipher:    nanotdf.CipherAES256GCM64, // Smallest tag
	}

	// Encrypt 1 byte
	nanoMinimal, _ := nanotdf.Encrypt([]byte("X"), minimalConfig)
	fmt.Printf("   ✓ 1-byte payload: %d bytes total\n", len(nanoMinimal))
	fmt.Println("   ✓ NanoTDF spec target: < 200 bytes overhead")

	// =====================
	// 8. Header Inspection
	// =====================
	fmt.Println("\n8. Header inspection...")

	reader, err := nanotdf.NewReader(nanoData, recipientKey)
	if err != nil {
		log.Fatalf("Failed to create reader: %v", err)
	}

	header := reader.Header()
	fmt.Printf("   ✓ Version: %d (NanoTDF v1 starts at 12)\n", header.Version)
	fmt.Printf("   ✓ Locator: %s\n", header.Locator.ToURL())
	fmt.Printf("   ✓ ECC Mode: %d (secp256r1)\n", header.ECCMode)
	fmt.Printf("   ✓ Symmetric Cipher: %d\n", header.SymmetricCipher)
	fmt.Printf("   ✓ Has Signature: %t\n", header.HasSignature)
	fmt.Printf("   ✓ Uses ECDSA Binding: %t\n", header.UseECDSABinding)
	fmt.Printf("   ✓ Ephemeral Key Size: %d bytes (compressed)\n", len(header.EphemeralPublicKey))

	reader.Close()

	fmt.Println("\n=== Example Complete ===")
}
