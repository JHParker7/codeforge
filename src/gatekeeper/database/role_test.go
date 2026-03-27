package database

import (
	"codeforge/src/gatekeeper/types"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func deleteRole(t *testing.T, id string) {
	t.Helper()
	conn := ConnectDB("codeforge")
	defer conn.Close(context.Background())
	conn.Exec(context.Background(), "DELETE FROM auth.roles WHERE id=$1", id)
}

func TestGetRole_ExistingRole(t *testing.T) {
	skipIfNoDB(t)
	id, _ := uuid.NewV7()
	role := types.Role{
		ID:        id.String(),
		CreatedAt: time.Now(),
		Permissions: types.Permissions{
			Valid: true,
			Permissions: []types.Permission{
				{
					Actions:  []string{"GetUser"},
					Services: []string{"Gatekeeper/User/" + id.String()},
				},
			},
		},
	}
	t.Cleanup(func() { deleteRole(t, role.ID) })
	CreateRole(role)

	got, err := GetRole(role.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != role.ID {
		t.Errorf("ID: got %q, want %q", got.ID, role.ID)
	}
	perms, ok := got.Permissions.(types.Permissions)
	if !ok {
		t.Fatalf("Permissions has unexpected type %T", got.Permissions)
	}
	if !perms.Valid {
		t.Error("expected Permissions.Valid to be true")
	}
	if len(perms.Permissions) == 0 {
		t.Fatal("expected at least one permission entry")
	}
	if perms.Permissions[0].Actions[0] != "GetUser" {
		t.Errorf("action: got %q, want %q", perms.Permissions[0].Actions[0], "GetUser")
	}
}

func TestGetRole_NotFound(t *testing.T) {
	skipIfNoDB(t)
	_, err := GetRole("00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Error("expected error for nonexistent role ID")
	}
}

func TestCreateRole_Success(t *testing.T) {
	skipIfNoDB(t)
	id, _ := uuid.NewV7()
	role := types.Role{
		ID:        id.String(),
		CreatedAt: time.Now(),
		Permissions: types.Permissions{
			Valid:       true,
			Permissions: []types.Permission{},
		},
	}
	t.Cleanup(func() { deleteRole(t, role.ID) })

	_, err := CreateRole(role)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCreateRole_WithPermissions(t *testing.T) {
	skipIfNoDB(t)
	id, _ := uuid.NewV7()
	role := types.Role{
		ID:        id.String(),
		CreatedAt: time.Now(),
		Permissions: types.Permissions{
			Valid: true,
			Permissions: []types.Permission{
				{
					Actions:  []string{"GetUser"},
					Services: []string{"Gatekeeper/User/" + id.String()},
					Teams:    []string{},
					Org:      "",
				},
			},
		},
	}
	t.Cleanup(func() { deleteRole(t, role.ID) })

	_, err := CreateRole(role)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
