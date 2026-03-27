package database

import (
	"codeforge/src/gatekeeper/types"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
)

func CreateRole(role types.Role) (string, error) {
	conn := ConnectDB("codeforge")
	slog.Info("adding new user to db")
	_, err := conn.Exec(
		context.Background(),
		"INSERT INTO auth.roles (id, created_at, updated_at, permissions) VALUES ($1,$2,$3,$4)",
		role.ID, role.CreatedAt, role.UpdatedAt, role.Permissions)
	if err != nil {
		return "", err
	}

	return "", nil
}

func GetRole(id string) (types.Role, error) {
	conn := ConnectDB("codeforge")
	var role types.Role
	var rawPerms json.RawMessage
	err := conn.QueryRow(
		context.Background(),
		"SELECT id, created_at, updated_at, permissions FROM auth.roles WHERE id=$1",
		id,
	).Scan(&role.ID, &role.CreatedAt, &role.UpdatedAt, &rawPerms)
	if err != nil {
		if err == pgx.ErrNoRows {
			return role, errors.New("role not found")
		}
		return role, err
	}
	if len(rawPerms) > 0 {
		var perms types.Permissions
		if err := json.Unmarshal(rawPerms, &perms); err != nil {
			return role, fmt.Errorf("failed to parse permissions: %w", err)
		}
		role.Permissions = perms
	}
	return role, nil
}
