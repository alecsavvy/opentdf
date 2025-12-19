package opentdf

import (
	"bytes"
	"io"
)

// Encrypt is a convenience function that encrypts data to TDF format.
// Returns the complete TDF archive as bytes.
func Encrypt(plaintext []byte, config EncryptConfig) ([]byte, error) {
	var buf bytes.Buffer

	w, err := NewWriter(&buf, config)
	if err != nil {
		return nil, err
	}

	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Decrypt is a convenience function that decrypts TDF data.
// Returns the decrypted plaintext.
func Decrypt(tdfData []byte, config DecryptConfig) ([]byte, error) {
	r, err := NewReader(tdfData, config)
	if err != nil {
		return nil, err
	}

	return r.ReadAll()
}

// EncryptReader encrypts data from an io.Reader to a TDF in a buffer.
// Returns the complete TDF archive as bytes.
func EncryptReader(src io.Reader, config EncryptConfig) ([]byte, error) {
	var buf bytes.Buffer

	w, err := NewWriter(&buf, config)
	if err != nil {
		return nil, err
	}

	if _, err := io.Copy(w, src); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncryptTo encrypts data from an io.Reader and writes the TDF to an io.Writer.
func EncryptTo(dst io.Writer, src io.Reader, config EncryptConfig) error {
	w, err := NewWriter(dst, config)
	if err != nil {
		return err
	}

	if _, err := io.Copy(w, src); err != nil {
		return err
	}

	return w.Close()
}
