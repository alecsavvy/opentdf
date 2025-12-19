// Example: Streaming Encryption for Large Files
//
// This example demonstrates:
// - Using io.Writer interface for streaming encryption
// - Using io.Reader interface for streaming decryption
// - Processing data in chunks without loading entire file into memory
// - Configuring segment sizes for optimal performance
//
// Run: go run ./examples/streaming/
package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"

	"github.com/opentdf/spec/pkg/crypto"
	"github.com/opentdf/spec/pkg/opentdf"
)

func main() {
	fmt.Println("=== OpenTDF Streaming Encryption Example ===\n")

	// Generate authority key
	authorityKey, err := crypto.GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	// Create a large test payload (5MB of random data)
	fmt.Println("1. Generating test data...")
	dataSize := 5 * 1024 * 1024 // 5MB
	testData := make([]byte, dataSize)
	if _, err := rand.Read(testData); err != nil {
		log.Fatalf("Failed to generate test data: %v", err)
	}
	fmt.Printf("   ✓ Generated %d bytes (%.1f MB) of test data\n", dataSize, float64(dataSize)/(1024*1024))

	// Configure encryption with custom segment size
	config := opentdf.EncryptConfig{
		Locator:            "streaming-example-authority",
		AuthorityPublicKey: &authorityKey.PublicKey,
		SegmentSize:        256 * 1024, // 256KB segments (smaller for demo)
		MIMEType:           "application/octet-stream",
	}

	// Stream encrypt
	fmt.Println("\n2. Streaming encryption...")
	var tdfBuffer bytes.Buffer

	writer, err := opentdf.NewWriter(&tdfBuffer, config)
	if err != nil {
		log.Fatalf("Failed to create writer: %v", err)
	}

	// Write data in chunks (simulating streaming from a file or network)
	chunkSize := 64 * 1024 // 64KB chunks
	totalWritten := 0

	for i := 0; i < len(testData); i += chunkSize {
		end := i + chunkSize
		if end > len(testData) {
			end = len(testData)
		}

		n, err := writer.Write(testData[i:end])
		if err != nil {
			log.Fatalf("Write failed at offset %d: %v", i, err)
		}
		totalWritten += n
	}

	if err := writer.Close(); err != nil {
		log.Fatalf("Close failed: %v", err)
	}

	fmt.Printf("   ✓ Written %d bytes in %d chunks\n", totalWritten, (len(testData)+chunkSize-1)/chunkSize)
	fmt.Printf("   ✓ TDF size: %d bytes\n", tdfBuffer.Len())

	// Inspect manifest to see segments
	m := writer.Manifest()
	fmt.Printf("   ✓ Segments created: %d\n", len(m.EncryptionInformation.IntegrityInformation.Segments))
	fmt.Printf("   ✓ Segment size: %d bytes\n", m.EncryptionInformation.IntegrityInformation.SegmentSizeDefault)

	// Stream decrypt
	fmt.Println("\n3. Streaming decryption...")

	reader, err := opentdf.NewReader(tdfBuffer.Bytes(), opentdf.DecryptConfig{
		PrivateKey: authorityKey,
	})
	if err != nil {
		log.Fatalf("Failed to create reader: %v", err)
	}

	// Read data in chunks
	var decryptedBuffer bytes.Buffer
	readChunkSize := 32 * 1024 // 32KB read chunks (different from write chunks)
	buf := make([]byte, readChunkSize)
	chunksRead := 0

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			decryptedBuffer.Write(buf[:n])
			chunksRead++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Read failed: %v", err)
		}
	}

	if err := reader.Close(); err != nil {
		log.Fatalf("Reader close failed: %v", err)
	}

	fmt.Printf("   ✓ Read %d bytes in %d chunks\n", decryptedBuffer.Len(), chunksRead)

	// Verify
	fmt.Println("\n4. Verifying data integrity...")
	if bytes.Equal(decryptedBuffer.Bytes(), testData) {
		fmt.Println("   ✓ Data integrity verified - decrypted matches original")
	} else {
		fmt.Println("   ✗ Data mismatch!")
	}

	// Memory efficiency note
	fmt.Println("\n5. Memory efficiency notes:")
	fmt.Printf("   • Peak memory during encryption: ~%d KB (segment size + buffer)\n", config.SegmentSize/1024+64)
	fmt.Printf("   • Peak memory during decryption: ~%d KB (segment size)\n", config.SegmentSize/1024)
	fmt.Println("   • Full file never needs to be in memory at once")

	fmt.Println("\n=== Example Complete ===")
}

