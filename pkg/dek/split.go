package dek

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidShareCount = errors.New("share count must be at least 2")
	ErrNoShares          = errors.New("no shares provided")
	ErrShareSizeMismatch = errors.New("all shares must have the same size")
	ErrInvalidShareSize  = errors.New("share size must match DEK size")
)

// Split divides a DEK into n shares using XOR-based secret sharing.
// All shares are required to reconstruct the original DEK.
//
// This implements the key splitting described in the TDF spec (security.md section 4).
// The algorithm:
// 1. Generate n-1 random shares
// 2. XOR all random shares together with the DEK to create the final share
// 3. XOR of all shares reconstructs the original DEK
//
// Each share can be wrapped with a different authority's public key,
// requiring all authorities to cooperate for decryption.
func Split(dek []byte, n int) ([][]byte, error) {
	if err := Validate(dek); err != nil {
		return nil, err
	}

	if n < 2 {
		return nil, ErrInvalidShareCount
	}

	shares := make([][]byte, n)

	// Generate n-1 random shares
	for i := 0; i < n-1; i++ {
		shares[i] = make([]byte, DEKSize)
		if _, err := io.ReadFull(rand.Reader, shares[i]); err != nil {
			return nil, fmt.Errorf("failed to generate random share: %w", err)
		}
	}

	// Calculate the final share: DEK XOR share[0] XOR share[1] XOR ... XOR share[n-2]
	finalShare := make([]byte, DEKSize)
	copy(finalShare, dek)

	for i := 0; i < n-1; i++ {
		for j := 0; j < DEKSize; j++ {
			finalShare[j] ^= shares[i][j]
		}
	}

	shares[n-1] = finalShare

	return shares, nil
}

// Combine reconstructs a DEK from its shares using XOR.
// All shares that were created by Split must be provided.
//
// The reconstruction: DEK = share[0] XOR share[1] XOR ... XOR share[n-1]
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) == 0 {
		return nil, ErrNoShares
	}

	// Verify all shares have the correct size
	for i, share := range shares {
		if len(share) != DEKSize {
			return nil, fmt.Errorf("%w: share %d has size %d", ErrInvalidShareSize, i, len(share))
		}
	}

	// XOR all shares together
	dek := make([]byte, DEKSize)
	copy(dek, shares[0])

	for i := 1; i < len(shares); i++ {
		for j := 0; j < DEKSize; j++ {
			dek[j] ^= shares[i][j]
		}
	}

	return dek, nil
}

// SplitShare represents a single share of a split DEK.
// Contains the share data and a unique identifier.
type SplitShare struct {
	// ID is a unique identifier for this share.
	// Maps to "sid" in the TDF spec.
	ID string

	// Share is the key share data.
	Share []byte
}

// SplitWithIDs divides a DEK into shares with assigned identifiers.
// The IDs are used to track which shares belong together.
func SplitWithIDs(dek []byte, ids []string) ([]SplitShare, error) {
	if len(ids) < 2 {
		return nil, ErrInvalidShareCount
	}

	shares, err := Split(dek, len(ids))
	if err != nil {
		return nil, err
	}

	result := make([]SplitShare, len(ids))
	for i, id := range ids {
		result[i] = SplitShare{
			ID:    id,
			Share: shares[i],
		}
	}

	return result, nil
}

// CombineFromSplitShares reconstructs a DEK from SplitShare objects.
func CombineFromSplitShares(splitShares []SplitShare) ([]byte, error) {
	shares := make([][]byte, len(splitShares))
	for i, ss := range splitShares {
		shares[i] = ss.Share
	}
	return Combine(shares)
}

