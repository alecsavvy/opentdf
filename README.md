# OpenTDF Go Library

[![Go Reference](https://pkg.go.dev/badge/github.com/alecsavvy/opentdf.svg)](https://pkg.go.dev/github.com/alecsavvy/opentdf)
[![Go Report Card](https://goreportcard.com/badge/github.com/alecsavvy/opentdf)](https://goreportcard.com/report/github.com/alecsavvy/opentdf)
[![CI](https://github.com/alecsavvy/opentdf/actions/workflows/ci.yml/badge.svg)](https://github.com/alecsavvy/opentdf/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/alecsavvy/opentdf)](https://go.dev/)
[![License](https://img.shields.io/github/license/alecsavvy/opentdf)](LICENSE)
[![OpenTDF Spec](https://img.shields.io/badge/OpenTDF_Spec-4.3.0-brightgreen.svg)](schema/OpenTDF/README.md)

**A pure Go implementation of the OpenTDF specification for data-centric encryption.**

This is a fork of [opentdf/spec](https://github.com/opentdf/spec) that adds a complete Go library for encrypting and decrypting data using the OpenTDF and NanoTDF formats.

## Features

- **Zero network dependencies** - Pure cryptographic operations, no HTTP clients
- **Streaming I/O** - `io.Reader`/`io.Writer` interfaces for memory-efficient large file handling
- **OpenTDF format** - ZIP-based container with JSON manifest
- **NanoTDF format** - Compact binary format for constrained environments
- **Key management** - DEK generation, wrapping, unwrapping, rewrapping, and splitting
- **Agnostic naming** - Uses "Authority" and "Locator" instead of "KAS" and "URL" for decentralized systems

## Installation

```bash
go get github.com/opentdf/spec
```

## Quick Start

```go
import (
    "github.com/opentdf/spec/pkg/crypto"
    "github.com/opentdf/spec/pkg/opentdf"
)

// Generate authority key
authorityKey, _ := crypto.GenerateRSAKeyPair(2048)

// Encrypt
tdfData, _ := opentdf.Encrypt(plaintext, opentdf.EncryptConfig{
    Locator:            "my-authority-id",
    AuthorityPublicKey: &authorityKey.PublicKey,
})

// Decrypt
decrypted, _ := opentdf.Decrypt(tdfData, opentdf.DecryptConfig{
    PrivateKey: authorityKey,
})
```

See [examples/](examples/) for more detailed usage.

## Packages

| Package | Description |
|---------|-------------|
| [`pkg/opentdf`](pkg/opentdf/) | OpenTDF encryption/decryption (ZIP + JSON manifest) |
| [`pkg/nanotdf`](pkg/nanotdf/) | NanoTDF compact binary format |
| [`pkg/crypto`](pkg/crypto/) | Cryptographic primitives (AES-GCM, RSA-OAEP, ECC, HMAC) |
| [`pkg/dek`](pkg/dek/) | DEK generation, wrapping, splitting |
| [`pkg/manifest`](pkg/manifest/) | Manifest struct definitions |

## Examples

```bash
go run ./examples/basic/           # Encrypt/decrypt round-trip
go run ./examples/streaming/       # Large file streaming
go run ./examples/key_management/  # Wrap, unwrap, rewrap, split
go run ./examples/nanotdf/         # NanoTDF compact format
```

## Spec Compatibility

This library implements **OpenTDF Specification v4.3.0**.
