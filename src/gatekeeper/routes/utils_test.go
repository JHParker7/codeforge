package routes

import (
	"crypto/ed25519"
	"testing"
)

// --- generateRandomString ---

func TestGenerateRandomString_ReturnsCorrectLength(t *testing.T) {
	for _, length := range []int{8, 16, 32, 64} {
		s, err := generateRandomString(length)
		if err != nil {
			t.Fatalf("length %d: unexpected error: %v", length, err)
		}
		if len(s) != length {
			t.Errorf("length %d: returned string has length %d", length, len(s))
		}
	}
}

func TestGenerateRandomString_IsUnique(t *testing.T) {
	a, _ := generateRandomString(32)
	b, _ := generateRandomString(32)
	if a == b {
		t.Error("expected different strings from successive calls")
	}
}

func TestGenerateRandomString_ContainsOnlyBase64URLChars(t *testing.T) {
	s, err := generateRandomString(64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, c := range s {
		valid := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !valid {
			t.Errorf("invalid character %q at position %d", c, i)
		}
	}
}

// --- bytesToEd25519PublicKey ---

func TestBytesToEd25519PublicKey_ValidLength(t *testing.T) {
	key := make([]byte, ed25519.PublicKeySize)
	pub, err := bytesToEd25519PublicKey(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("returned key length: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}

func TestBytesToEd25519PublicKey_PreservesBytes(t *testing.T) {
	input := make([]byte, ed25519.PublicKeySize)
	for i := range input {
		input[i] = byte(i)
	}
	pub, err := bytesToEd25519PublicKey(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, b := range input {
		if pub[i] != b {
			t.Errorf("byte %d: got %d, want %d", i, pub[i], b)
		}
	}
}

func TestBytesToEd25519PublicKey_TooShort(t *testing.T) {
	_, err := bytesToEd25519PublicKey(make([]byte, ed25519.PublicKeySize-1))
	if err == nil {
		t.Error("expected error for key shorter than 32 bytes")
	}
}

func TestBytesToEd25519PublicKey_TooLong(t *testing.T) {
	_, err := bytesToEd25519PublicKey(make([]byte, ed25519.PublicKeySize+1))
	if err == nil {
		t.Error("expected error for key longer than 32 bytes")
	}
}

func TestBytesToEd25519PublicKey_Empty(t *testing.T) {
	_, err := bytesToEd25519PublicKey([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}
