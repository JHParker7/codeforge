package auth

import (
	"codeforge/src/gatekeeper/types"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return pub, priv
}

var testUser = types.User{
	ID:       "019c5df7-7e21-73fd-9641-d0e9208a927e",
	Username: "testuser",
	Email:    "test@example.com",
}

// --- CreateJWT ---

func TestCreateJWT_ReturnsNonEmptyToken(t *testing.T) {
	_, priv := newTestKeyPair(t)
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour))

	token, err := CreateJWT(testUser, exp, priv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token string")
	}
}

func TestCreateJWT_ClaimsAreCorrect(t *testing.T) {
	_, priv := newTestKeyPair(t)
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour))

	tokenStr, _ := CreateJWT(testUser, exp, priv)

	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return priv.Public(), nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}

	claims := parsed.Claims.(jwt.MapClaims)
	if claims["username"] != testUser.Username {
		t.Errorf("username: got %v, want %v", claims["username"], testUser.Username)
	}
	if claims["email"] != testUser.Email {
		t.Errorf("email: got %v, want %v", claims["email"], testUser.Email)
	}
	if claims["id"] != testUser.ID {
		t.Errorf("id: got %v, want %v", claims["id"], testUser.ID)
	}
	if claims["authorized"] != true {
		t.Errorf("authorized: got %v, want true", claims["authorized"])
	}
	if claims["exp"].(float64) != float64(exp.Unix()) {
		t.Errorf("exp: got %v, want %v", claims["exp"], float64(exp.Unix()))
	}
}

func TestCreateJWT_SignatureVerifiableWithPublicKey(t *testing.T) {
	pub, priv := newTestKeyPair(t)
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour))

	tokenStr, _ := CreateJWT(testUser, exp, priv)

	_, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return pub, nil
	})
	if err != nil {
		t.Errorf("token should verify with matching public key: %v", err)
	}
}

func TestCreateJWT_ExpiredTokenIsRejected(t *testing.T) {
	_, priv := newTestKeyPair(t)
	exp := jwt.NewNumericDate(time.Now().Add(-time.Minute))

	tokenStr, _ := CreateJWT(testUser, exp, priv)

	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return priv.Public(), nil
	})
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
	if parsed != nil && parsed.Valid {
		t.Error("expired token should not be marked valid")
	}
}

// --- CheckJWT ---

func TestCheckJWT_ValidToken(t *testing.T) {
	pub, priv := newTestKeyPair(t)
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour))
	tokenStr, _ := CreateJWT(testUser, exp, priv)

	claim, err := CheckJWT(tokenStr, testUser, pub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !claim.Authorized {
		t.Error("expected Authorized to be true")
	}
	if claim.Username != testUser.Username {
		t.Errorf("Username: got %v, want %v", claim.Username, testUser.Username)
	}
	if claim.Email != testUser.Email {
		t.Errorf("Email: got %v, want %v", claim.Email, testUser.Email)
	}
	if claim.ID != testUser.ID {
		t.Errorf("ID: got %v, want %v", claim.ID, testUser.ID)
	}
	if claim.Exp != float64(exp.Unix()) {
		t.Errorf("Exp: got %v, want %v", claim.Exp, float64(exp.Unix()))
	}
}

func TestCheckJWT_ExpiredToken(t *testing.T) {
	pub, priv := newTestKeyPair(t)
	exp := jwt.NewNumericDate(time.Now().Add(-time.Minute))
	tokenStr, _ := CreateJWT(testUser, exp, priv)

	_, err := CheckJWT(tokenStr, testUser, pub)
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestCheckJWT_EmailMismatch(t *testing.T) {
	pub, priv := newTestKeyPair(t)
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour))
	tokenStr, _ := CreateJWT(testUser, exp, priv)

	wrongUser := testUser
	wrongUser.Email = "other@example.com"

	claim, err := CheckJWT(tokenStr, wrongUser, pub)
	if err == nil {
		t.Error("expected error for email mismatch")
	}
	if claim.Authorized {
		t.Error("expected Authorized to be false on email mismatch")
	}
}

func TestCheckJWT_UsernameMismatch(t *testing.T) {
	pub, priv := newTestKeyPair(t)
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour))
	tokenStr, _ := CreateJWT(testUser, exp, priv)

	wrongUser := testUser
	wrongUser.Username = "otheruser"

	claim, err := CheckJWT(tokenStr, wrongUser, pub)
	if err == nil {
		t.Error("expected error for username mismatch")
	}
	if claim.Authorized {
		t.Error("expected Authorized to be false on username mismatch")
	}
}

func TestCheckJWT_IDMismatch(t *testing.T) {
	pub, priv := newTestKeyPair(t)
	exp := jwt.NewNumericDate(time.Now().Add(time.Hour))
	tokenStr, _ := CreateJWT(testUser, exp, priv)

	wrongUser := testUser
	wrongUser.ID = "00000000-0000-0000-0000-000000000000"

	claim, err := CheckJWT(tokenStr, wrongUser, pub)
	if err == nil {
		t.Error("expected error for ID mismatch")
	}
	if claim.Authorized {
		t.Error("expected Authorized to be false on ID mismatch")
	}
}
