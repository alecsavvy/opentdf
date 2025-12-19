# OpenTDF Go Library

A pure Go library implementing the OpenTDF and NanoTDF specifications for data-centric encryption.

## Features

- **OpenTDF Format**: ZIP-based archive with JSON manifest, streaming encryption/decryption
- **NanoTDF Format**: Compact binary format for resource-constrained environments
- **Zero Network Dependencies**: KAS/authority locator is just a string - no HTTP clients
- **Streaming I/O**: Uses `io.Reader`/`io.Writer` interfaces for memory efficiency
- **DEK Management**: Generate, wrap, unwrap, rewrap, and split Data Encryption Keys
- **Policy Binding**: Cryptographic binding between policies and keys

## Naming Convention

The library uses system-agnostic naming to support both traditional and decentralized systems:

| TDF Spec Term | Library Term | Description |
|---------------|--------------|-------------|
| KAS (Key Access Server) | **Authority** | Entity responsible for key access decisions |
| KAS URL | **Locator** | Identifier (URL, chain ID, DID, etc.) |
| Key ID (kid) | **KeyID** | Identifier for a specific key |
| Split ID (sid) | **SplitID** | Identifier for a key share |

## Installation

```bash
go get github.com/opentdf/spec/pkg
```

## Quick Start

### OpenTDF Encryption/Decryption

```go
package main

import (
    "crypto/rsa"
    "fmt"
    
    "github.com/opentdf/spec/pkg/crypto"
    "github.com/opentdf/spec/pkg/manifest"
    "github.com/opentdf/spec/pkg/opentdf"
)

func main() {
    // Generate authority key pair (in practice, this comes from your key management)
    authorityKey, _ := crypto.GenerateRSAKeyPair(2048)
    
    // Create a policy
    policy := manifest.NewPolicy()
    policy.AddAttribute("https://example.com/attr/classification/value/confidential")
    
    // Encrypt
    config := opentdf.EncryptConfig{
        Locator:            "blockchain:chain-123", // Can be any identifier
        AuthorityPublicKey: &authorityKey.PublicKey,
        Policy:             policy,
        MIMEType:           "text/plain",
    }
    
    plaintext := []byte("Sensitive data to protect")
    tdfData, err := opentdf.Encrypt(plaintext, config)
    if err != nil {
        panic(err)
    }
    
    // Decrypt (requires the private key)
    decryptConfig := opentdf.DecryptConfig{
        PrivateKey: authorityKey,
    }
    
    decrypted, err := opentdf.Decrypt(tdfData, decryptConfig)
    if err != nil {
        panic(err)
    }
    
    fmt.Println(string(decrypted)) // "Sensitive data to protect"
}
```

### NanoTDF Encryption/Decryption

```go
package main

import (
    "fmt"
    
    "github.com/opentdf/spec/pkg/crypto"
    "github.com/opentdf/spec/pkg/nanotdf"
)

func main() {
    // Generate ECC key pair for NanoTDF
    recipientKey, _ := crypto.GenerateECCKeyPair(nanotdf.ECCModeSecp256r1)
    
    config := nanotdf.Config{
        Locator:            "kas.example.com",
        RecipientPublicKey: &recipientKey.PublicKey,
        ECCMode:            nanotdf.ECCModeSecp256r1,
        SymmetricCipher:    nanotdf.CipherAES256GCM128,
    }
    
    plaintext := []byte("Compact encrypted message")
    nanoData, _ := nanotdf.Encrypt(plaintext, config)
    
    // NanoTDF is very compact - typically under 200 bytes overhead
    fmt.Printf("NanoTDF size: %d bytes\n", len(nanoData))
    
    // Decrypt
    decrypted, _ := nanotdf.Decrypt(nanoData, recipientKey)
    fmt.Println(string(decrypted))
}
```

### DEK Management

```go
package main

import (
    "github.com/opentdf/spec/pkg/crypto"
    "github.com/opentdf/spec/pkg/dek"
)

func main() {
    // Generate a new DEK
    key, _ := dek.Generate()
    
    // Generate authority keys
    authorityKey, _ := crypto.GenerateRSAKeyPair(2048)
    recipientKey, _ := crypto.GenerateRSAKeyPair(2048)
    
    // Wrap DEK with authority's public key
    wrapped, _ := dek.Wrap(key, &authorityKey.PublicKey)
    
    // Rewrap for a recipient (this is what the authority does)
    rewrapped, _ := dek.Rewrap(wrapped, authorityKey, &recipientKey.PublicKey)
    
    // Recipient unwraps
    unwrapped, _ := dek.Unwrap(rewrapped, recipientKey)
    
    // Split DEK across multiple authorities
    shares, _ := dek.Split(key, 3)
    reconstructed, _ := dek.Combine(shares)
    
    // Calculate policy binding
    policyB64 := "eyJ1dWlkIjoiMTIzNCJ9" // Base64-encoded policy
    binding, _ := dek.CalculatePolicyBinding(key, policyB64)
    
    // Verify binding
    err := dek.VerifyPolicyBinding(key, policyB64, binding)
}
```

### Streaming Encryption

```go
package main

import (
    "io"
    "os"
    
    "github.com/opentdf/spec/pkg/crypto"
    "github.com/opentdf/spec/pkg/opentdf"
)

func main() {
    authorityKey, _ := crypto.GenerateRSAKeyPair(2048)
    
    // Create TDF output file
    outFile, _ := os.Create("document.pdf.tdf")
    defer outFile.Close()
    
    config := opentdf.EncryptConfig{
        Locator:            "my-authority",
        AuthorityPublicKey: &authorityKey.PublicKey,
        SegmentSize:        1024 * 1024, // 1MB segments
        MIMEType:           "application/pdf",
    }
    
    // Create streaming writer
    writer, _ := opentdf.NewWriter(outFile, config)
    
    // Stream data from source
    srcFile, _ := os.Open("document.pdf")
    defer srcFile.Close()
    
    io.Copy(writer, srcFile)
    writer.Close()
}
```

## Package Structure

```
pkg/
├── crypto/     # Cryptographic primitives (AES-GCM, RSA-OAEP, ECC, HMAC, HKDF)
├── dek/        # DEK management (generate, wrap, unwrap, rewrap, split)
├── manifest/   # OpenTDF manifest JSON structures
├── opentdf/    # OpenTDF format (ZIP archive with streaming)
├── nanotdf/    # NanoTDF format (compact binary)
└── types/      # Shared types
```

## Dependencies

- `golang.org/x/crypto/hkdf` - HKDF key derivation
- `github.com/google/uuid` - UUID generation for policies

All cryptographic operations use Go's standard library (`crypto/*`).

## Testing

```bash
go test ./pkg/... -v
```

## Specification Compliance

This library implements:
- **OpenTDF Specification v4.3.0** - Full manifest schema, ZIP packaging, streaming
- **NanoTDF Specification** - Binary format, all ECC modes, variable tag sizes

See the [schema/](../schema/) directory for the complete specifications.

