package database

import (
	"codeforge/src/gatekeeper/types"
	"context"
	"log/slog"
)

func CreateSession(session types.Session) (string, error) {
	conn := ConnectDB("codeforge")
	slog.Info("adding new user to db")
	_, err := conn.Exec(
		context.Background(),
		"INSERT INTO auth.sessions (id, created_at, updated_at, token, expires_at, user_id, pub_key) VALUES ($1,$2,$3,$4,$5,$6,$7)",
		session.ID, session.CreatedAt, session.UpdatedAt, session.Token, session.ExpiresAt, session.UserID, session.PubKey)
	if err != nil {
		return "", err
	}
	return "", nil
}

func GetSession(token string) (types.Session, error) {
	conn := ConnectDB("codeforge")

	var session types.Session
	slog.Info("getting session info")
	conn.QueryRow(context.Background(), "SELECT id, created_at, updated_at, token, expires_at, user_id, pub_key FROM auth.sessions WHERE token=$1", token).Scan(&session.ID, &session.CreatedAt, &session.UpdatedAt, &session.Token, &session.ExpiresAt, &session.UserID, &session.PubKey)
	slog.Info("session_id", "uuid", session.ID)
	return session, nil
}
