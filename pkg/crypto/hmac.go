package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var (
	ErrPolicyBindingMismatch = errors.New("policy binding verification failed: hash mismatch")
)

// HMACSHA256 computes HMAC-SHA256 of the message using the provided key.
func HMACSHA256(key, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

// CalculatePolicyBinding computes the policy binding hash.
// The binding is: HMAC-SHA256(DEK, Base64EncodedPolicy)
// This binds the policy to the DEK, preventing policy tampering.
//
// In the TDF spec, this is used in the policyBinding.hash field of KeyAccess objects.
func CalculatePolicyBinding(dek []byte, policyBase64 string) string {
	// The policy is already Base64 encoded as stored in the manifest
	policyBytes := []byte(policyBase64)

	// Compute HMAC
	binding := HMACSHA256(dek, policyBytes)

	// Return as Base64
	return base64.StdEncoding.EncodeToString(binding)
}

// VerifyPolicyBinding verifies that the policy binding hash is correct.
// Returns nil if valid, ErrPolicyBindingMismatch if invalid.
func VerifyPolicyBinding(dek []byte, policyBase64, expectedHashBase64 string) error {
	computed := CalculatePolicyBinding(dek, policyBase64)

	if !hmac.Equal([]byte(computed), []byte(expectedHashBase64)) {
		return ErrPolicyBindingMismatch
	}

	return nil
}

// CalculateRootSignature computes the root signature over all segment hashes.
// The signature is: HMAC-SHA256(DEK, concatenation of all segment hashes)
//
// In the TDF spec, this is used in integrityInformation.rootSignature.sig
func CalculateRootSignature(dek []byte, segmentHashes [][]byte) string {
	// Concatenate all segment hashes
	var combined []byte
	for _, hash := range segmentHashes {
		combined = append(combined, hash...)
	}

	// Compute HMAC
	sig := HMACSHA256(dek, combined)

	// Return as Base64
	return base64.StdEncoding.EncodeToString(sig)
}

// VerifyRootSignature verifies the root signature over segment hashes.
func VerifyRootSignature(dek []byte, segmentHashes [][]byte, expectedSigBase64 string) error {
	computed := CalculateRootSignature(dek, segmentHashes)

	if !hmac.Equal([]byte(computed), []byte(expectedSigBase64)) {
		return errors.New("root signature verification failed")
	}

	return nil
}

// CalculateSegmentHash computes the hash/tag for a single segment.
// For GMAC, this is the authentication tag from AES-GCM encryption.
// For HMAC, this would be HMAC-SHA256(DEK, segment).
func CalculateSegmentHash(dek, segment []byte) []byte {
	return HMACSHA256(dek, segment)
}
