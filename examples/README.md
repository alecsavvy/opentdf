# OpenTDF Go Library Examples

This directory contains runnable examples demonstrating the OpenTDF Go library.

## Prerequisites

```bash
# From the repository root
go mod tidy
```

## Examples

### 1. Basic Encryption/Decryption

Demonstrates the fundamentals of OpenTDF:
- Generating authority keys
- Creating policies with attributes
- Encrypting and decrypting data

```bash
go run ./examples/basic/
```

**Output:**
```
=== OpenTDF Basic Encryption/Decryption Example ===

1. Generating RSA key pair for the authority...
   ✓ RSA-2048 key pair generated

2. Creating access policy...
   ✓ Policy created with UUID: ...
   ✓ Attributes: 2
   ✓ Dissemination list: [alice@example.com bob@example.com]

3. Encrypting data...
   ✓ Plaintext size: 123 bytes
   ✓ TDF size: 1847 bytes (ZIP archive)
...
```

### 2. Streaming Encryption

Demonstrates memory-efficient encryption of large files:
- Using `io.Writer` for streaming encryption
- Using `io.Reader` for streaming decryption
- Configuring segment sizes

```bash
go run ./examples/streaming/
```

### 3. Key Management

Demonstrates DEK (Data Encryption Key) operations:
- Generating DEKs
- Wrapping/unwrapping with RSA keys
- Rewrapping for different recipients
- Key splitting across multiple authorities
- Policy binding for tamper detection

```bash
go run ./examples/key_management/
```

### 4. NanoTDF Format

Demonstrates the compact NanoTDF binary format:
- Different ECC curves (secp256r1, secp384r1, secp521r1)
- Variable GCM tag sizes (64-128 bit)
- ECDSA policy binding
- Creator signatures
- Embedded policies

```bash
go run ./examples/nanotdf/
```

## Terminology

The library uses agnostic naming to support decentralized systems:

| TDF Spec Term | Library Term | Description |
|---------------|--------------|-------------|
| KAS (Key Access Server) | Authority | Entity controlling key access |
| KAS URL | Locator | Identifier (URL, chain ID, DID) |
| kid | KeyID | Key identifier |
| sid | SplitID | Key share identifier |

## Common Patterns

### Encrypt Data

```go
import (
    "github.com/opentdf/spec/pkg/crypto"
    "github.com/opentdf/spec/pkg/opentdf"
)

// Generate or load authority key
authorityKey, _ := crypto.GenerateRSAKeyPair(2048)

// Encrypt
config := opentdf.EncryptConfig{
    Locator:            "my-authority-id",
    AuthorityPublicKey: &authorityKey.PublicKey,
}
tdfData, _ := opentdf.Encrypt(plaintext, config)
```

### Decrypt Data

```go
decrypted, _ := opentdf.Decrypt(tdfData, opentdf.DecryptConfig{
    PrivateKey: authorityKey,
})
```

### NanoTDF (Compact Format)

```go
import (
    "github.com/opentdf/spec/pkg/crypto"
    "github.com/opentdf/spec/pkg/nanotdf"
)

// Generate ECC key
recipientKey, _ := crypto.GenerateECCKeyPair(nanotdf.ECCModeSecp256r1)

// Encrypt
config := nanotdf.Config{
    Locator:            "my-authority",
    RecipientPublicKey: &recipientKey.PublicKey,
    ECCMode:            nanotdf.ECCModeSecp256r1,
}
nanoData, _ := nanotdf.Encrypt(plaintext, config)

// Decrypt
decrypted, _ := nanotdf.Decrypt(nanoData, recipientKey)
```

## Integration with Real Systems

In production systems, you would typically:

1. **Authority/KAS Integration**: The authority holds the private key and performs rewrap operations after verifying the requester's attributes
2. **Policy Enforcement**: The authority validates that the requester's attributes satisfy the policy before releasing keys
3. **Key Management**: Use proper key management (HSM, KMS) instead of generating keys inline

See the [TDF specification](../schema/) for complete details on the access control flow.

