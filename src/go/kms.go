// kms.go — a small envelope-encryption / key-management helper.
// Expected CBOM: AES key wrap (KW), HKDF-SHA256 key derivation, AES-256-GCM
// data-encryption. Represents a KMS-style "wrap a DEK with a KEK" flow — the
// kind of key hierarchy KMS-003 asks about.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
	"io"
)

// deriveDEK — HKDF-SHA256 derives a data-encryption key from a master secret.
func deriveDEK(master, salt, info []byte) ([]byte, error) {
	dek := make([]byte, 32)
	r := hkdf.New(sha256.New, master, salt, info)
	_, err := io.ReadFull(r, dek)
	return dek, err
}

// wrapDEK — AES key-wrap style: encrypt the DEK under the KEK with AES-GCM.
func wrapDEK(kek, dek []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek) // AES-256 KEK
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, dek, nil), nil
}
