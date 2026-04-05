package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, keySize)
	plaintext := []byte("hello")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatalf("expected ciphertext to differ from plaintext")
	}

	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("unexpected plaintext: %s", string(decrypted))
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	key := bytes.Repeat([]byte{0x22}, keySize)
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	if !bytes.Equal(loaded, key) {
		t.Fatalf("unexpected key data")
	}
}

func TestLoadKeyInvalidSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	key := bytes.Repeat([]byte{0x33}, keySize-1)
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if _, err := LoadKey(path); err == nil {
		t.Fatalf("expected error for invalid key length")
	}
}
