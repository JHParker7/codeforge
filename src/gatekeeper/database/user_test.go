package database

import (
	"codeforge/src/gatekeeper/types"
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

const testPassword = "unit_test_password"

// skipIfNoDB skips the test if DATABASE_URL is not set.
func skipIfNoDB(t *testing.T) {
	t.Helper()
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set")
	}
}

// makeTestUser returns a User with a proper Argon2 hash for testPassword.
// Every call produces a unique username / email / ID.
// The full UUID (dashes stripped) is used as the suffix so that sequential
// V7 UUIDs — which share the same millisecond-precision prefix — still produce
// distinct usernames and emails.
func makeTestUser() types.User {
	id, _ := uuid.NewV7()
	unique := strings.ReplaceAll(id.String(), "-", "") // 32 unique hex chars
	salt := "unit_test_static_salt"
	hash := hex.EncodeToString(argon2.IDKey(
		[]byte(testPassword), []byte(salt), 1, 64*1024, 4, 32,
	))
	return types.User{
		ID:       id.String(),
		Username: "u" + unique,
		Email:    "u" + unique + "@t.l",
		Password: hash,
		Salt:     salt,
		Active:   true,
	}
}

// deleteUser removes the user and any sessions referencing it.
func deleteUser(t *testing.T, id string) {
	t.Helper()
	conn := ConnectDB("codeforge")
	defer conn.Close(context.Background())
	conn.Exec(context.Background(), "DELETE FROM auth.sessions WHERE user_id=$1", id)
	conn.Exec(context.Background(), "DELETE FROM auth.users WHERE id=$1", id)
}

// --- CreateUser ---

func TestCreateUser_Success(t *testing.T) {
	skipIfNoDB(t)
	user := makeTestUser()
	t.Cleanup(func() { deleteUser(t, user.ID) })

	result, err := CreateUser(user)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != user.ID {
		t.Errorf("returned ID: got %q, want %q", result, user.ID)
	}
}

func TestCreateUser_DuplicateUsername(t *testing.T) {
	skipIfNoDB(t)
	user := makeTestUser()
	t.Cleanup(func() { deleteUser(t, user.ID) })
	CreateUser(user)

	dup := makeTestUser()
	dup.Username = user.Username // same username, different email + ID
	t.Cleanup(func() { deleteUser(t, dup.ID) })

	result, err := CreateUser(dup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "username taken" {
		t.Errorf("expected %q, got %q", "username taken", result)
	}
}

func TestCreateUser_DuplicateEmail(t *testing.T) {
	skipIfNoDB(t)
	user := makeTestUser()
	t.Cleanup(func() { deleteUser(t, user.ID) })
	CreateUser(user)

	dup := makeTestUser()
	dup.Email = user.Email // same email, different username + ID
	t.Cleanup(func() { deleteUser(t, dup.ID) })

	result, err := CreateUser(dup)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "email in use" {
		t.Errorf("expected %q, got %q", "email in use", result)
	}
}

// --- AuthUser ---

func TestAuthUser_CorrectPassword(t *testing.T) {
	skipIfNoDB(t)
	user := makeTestUser()
	t.Cleanup(func() { deleteUser(t, user.ID) })
	CreateUser(user)

	id, err := AuthUser(user.Username, testPassword)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != user.ID {
		t.Errorf("returned ID: got %q, want %q", id, user.ID)
	}
}

func TestAuthUser_WrongPassword(t *testing.T) {
	skipIfNoDB(t)
	user := makeTestUser()
	t.Cleanup(func() { deleteUser(t, user.ID) })
	CreateUser(user)

	result, err := AuthUser(user.Username, "wrong_password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "incorrect username or password" {
		t.Errorf("expected auth failure, got %q", result)
	}
}

func TestAuthUser_NonExistentUser(t *testing.T) {
	skipIfNoDB(t)

	result, err := AuthUser("unit_no_such_user", "anypass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "incorrect username or password" {
		t.Errorf("expected auth failure, got %q", result)
	}
}

// --- GetUser ---

func TestDeleteUser_SoftDeletes(t *testing.T) {
	skipIfNoDB(t)
	user := makeTestUser()
	t.Cleanup(func() { deleteUser(t, user.ID) })
	CreateUser(user)

	if err := DeleteUser(user.ID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// GetUser filters on active=true; deleted user should not be found
	got := GetUser(user.ID)
	if got.ID != "" {
		t.Errorf("expected empty User after delete, got ID %q", got.ID)
	}
}

func TestDeleteUser_NonExistent(t *testing.T) {
	skipIfNoDB(t)
	err := DeleteUser("00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Error("expected error deleting nonexistent user")
	}
}

func TestUpdateUser_UpdatesFields(t *testing.T) {
	skipIfNoDB(t)
	user := makeTestUser()
	t.Cleanup(func() { deleteUser(t, user.ID) })
	CreateUser(user)

	newUsername := user.Username + "_upd"
	newEmail := newUsername + "@t.l"

	if err := UpdateUser(types.User{
		ID:       user.ID,
		Username: newUsername,
		Email:    newEmail,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := GetUser(user.ID)
	if got.Username != newUsername {
		t.Errorf("Username: got %q, want %q", got.Username, newUsername)
	}
	if got.Email != newEmail {
		t.Errorf("Email: got %q, want %q", got.Email, newEmail)
	}
}

func TestUpdateUser_NonExistent(t *testing.T) {
	skipIfNoDB(t)
	err := UpdateUser(types.User{
		ID:       "00000000-0000-0000-0000-000000000000",
		Username: "x",
		Email:    "x@t.l",
	})
	if err == nil {
		t.Error("expected error updating nonexistent user")
	}
}

func TestGetUser_ExistingUser(t *testing.T) {
	skipIfNoDB(t)
	user := makeTestUser()
	t.Cleanup(func() { deleteUser(t, user.ID) })
	CreateUser(user)

	got := GetUser(user.ID)
	if got.ID != user.ID {
		t.Errorf("ID: got %q, want %q", got.ID, user.ID)
	}
	if got.Username != user.Username {
		t.Errorf("Username: got %q, want %q", got.Username, user.Username)
	}
	if got.Email != user.Email {
		t.Errorf("Email: got %q, want %q", got.Email, user.Email)
	}
}

func TestGetUser_NonExistent(t *testing.T) {
	skipIfNoDB(t)

	got := GetUser("00000000-0000-0000-0000-000000000000")
	if got.ID != "" {
		t.Errorf("expected empty User for nonexistent ID, got ID %q", got.ID)
	}
}
