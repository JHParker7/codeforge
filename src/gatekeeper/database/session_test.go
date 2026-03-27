package database

import (
	"codeforge/src/gatekeeper/types"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func deleteSession(t *testing.T, id string) {
	t.Helper()
	conn := ConnectDB("codeforge")
	defer conn.Close(context.Background())
	conn.Exec(context.Background(), "DELETE FROM auth.sessions WHERE id=$1", id)
}

func makeTestSession(userID string) types.Session {
	id, _ := uuid.NewV7()
	return types.Session{
		ID:        id.String(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Token:     "unit_test_token_" + id.String(),
		UserID:    userID,
		PubKey:    make([]byte, 32),
	}
}

func TestCreateSession_Success(t *testing.T) {
	skipIfNoDB(t)
	user := makeTestUser()
	t.Cleanup(func() { deleteUser(t, user.ID) })
	CreateUser(user)

	session := makeTestSession(user.ID)
	t.Cleanup(func() { deleteSession(t, session.ID) })

	_, err := CreateSession(session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetSession_ExistingToken(t *testing.T) {
	skipIfNoDB(t)
	user := makeTestUser()
	t.Cleanup(func() { deleteUser(t, user.ID) })
	CreateUser(user)

	session := makeTestSession(user.ID)
	t.Cleanup(func() { deleteSession(t, session.ID) })
	CreateSession(session)

	got, err := GetSession(session.Token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != session.ID {
		t.Errorf("ID: got %q, want %q", got.ID, session.ID)
	}
	if got.UserID != session.UserID {
		t.Errorf("UserID: got %q, want %q", got.UserID, session.UserID)
	}
	if got.Token != session.Token {
		t.Errorf("Token: got %q, want %q", got.Token, session.Token)
	}
}

func TestGetSession_NotFound(t *testing.T) {
	skipIfNoDB(t)

	_, err := GetSession("unit_test_nonexistent_token_xyz")
	if err == nil {
		t.Error("expected error for nonexistent token, got nil")
	}
}
