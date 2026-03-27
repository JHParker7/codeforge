package auth

import (
	"codeforge/src/gatekeeper/types"
	"database/sql"
	"fmt"
	"testing"
)

// --- HasPermission ---

func roleWithPermission(userID string) types.Role {
	return types.Role{
		ID: "role-1",
		Permissions: types.Permissions{
			Valid: true,
			Permissions: []types.Permission{
				{
					Actions:  []string{"GetUser", "PutUser", "DeleteUser"},
					Services: []string{fmt.Sprintf("Gatekeeper/User/%s", userID)},
				},
			},
		},
	}
}

func TestHasPermission_MatchingActionAndService(t *testing.T) {
	role := roleWithPermission("user-abc")
	if !HasPermission(role, "GetUser", "Gatekeeper/User/user-abc") {
		t.Error("expected HasPermission to return true for matching action and service")
	}
}

func TestHasPermission_WrongAction(t *testing.T) {
	role := roleWithPermission("user-abc")
	if HasPermission(role, "AdminAction", "Gatekeeper/User/user-abc") {
		t.Error("expected HasPermission to return false for an action not in the role")
	}
}

func TestHasPermission_WrongService(t *testing.T) {
	role := roleWithPermission("user-abc")
	if HasPermission(role, "GetUser", "Gatekeeper/User/other-user") {
		t.Error("expected HasPermission to return false for a different user's service path")
	}
}

func TestHasPermission_EmptyPermissions(t *testing.T) {
	role := types.Role{
		ID: "role-empty",
		Permissions: types.Permissions{
			Valid:       true,
			Permissions: []types.Permission{},
		},
	}
	if HasPermission(role, "GetUser", "Gatekeeper/User/user-abc") {
		t.Error("expected HasPermission to return false for a role with no permissions")
	}
}

func TestHasPermission_NilPermissionsType(t *testing.T) {
	role := types.Role{ID: "role-nil", Permissions: nil}
	if HasPermission(role, "GetUser", "Gatekeeper/User/user-abc") {
		t.Error("expected HasPermission to return false when Permissions field is nil")
	}
}

func TestCreateEmptyUserRole_HasNonEmptyID(t *testing.T) {
	user := types.User{ID: "abc-123"}
	role := CreateEmptyUserRole(user)
	if role.ID == "" {
		t.Error("expected non-empty role ID")
	}
}

func TestCreateEmptyUserRole_IDsAreUnique(t *testing.T) {
	user := types.User{ID: "abc-123"}
	r1 := CreateEmptyUserRole(user)
	r2 := CreateEmptyUserRole(user)
	if r1.ID == r2.ID {
		t.Error("expected a unique ID per call, got the same ID twice")
	}
}

func TestCreateEmptyUserRole_PermissionsValid(t *testing.T) {
	user := types.User{ID: "abc-123"}
	role := CreateEmptyUserRole(user)

	perms, ok := role.Permissions.(types.Permissions)
	if !ok {
		t.Fatalf("Permissions has unexpected type %T", role.Permissions)
	}
	if !perms.Valid {
		t.Error("expected Permissions.Valid to be true")
	}
}

func TestCreateEmptyUserRole_ServicePath(t *testing.T) {
	user := types.User{ID: "abc-123"}
	role := CreateEmptyUserRole(user)

	perms := role.Permissions.(types.Permissions)
	if len(perms.Permissions) == 0 {
		t.Fatal("expected at least one permission entry")
	}

	want := fmt.Sprintf("Gatekeeper/User/%s", user.ID)
	found := false
	for _, s := range perms.Permissions[0].Services {
		if s == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("service path %q not found in %v", want, perms.Permissions[0].Services)
	}
}

func TestCreateEmptyUserRole_Actions(t *testing.T) {
	user := types.User{ID: "abc-123"}
	role := CreateEmptyUserRole(user)

	perms := role.Permissions.(types.Permissions)
	actions := perms.Permissions[0].Actions

	wantActions := map[string]bool{
		"DeleteUser": false,
		"GetUser":    false,
		"PutUser":    false,
	}
	for _, a := range actions {
		if _, ok := wantActions[a]; !ok {
			t.Errorf("unexpected action %q", a)
		}
		wantActions[a] = true
	}
	for action, found := range wantActions {
		if !found {
			t.Errorf("missing expected action %q", action)
		}
	}
}

func TestCreateEmptyUserRole_TeamAndOrgPropagated(t *testing.T) {
	user := types.User{
		ID:     "abc-123",
		TeamID: sql.NullString{String: "team-xyz", Valid: true},
		OrgID:  sql.NullString{String: "org-abc", Valid: true},
	}
	role := CreateEmptyUserRole(user)

	perms := role.Permissions.(types.Permissions)
	perm := perms.Permissions[0]

	if len(perm.Teams) == 0 || perm.Teams[0] != user.TeamID.String {
		t.Errorf("Teams: got %v, want [%q]", perm.Teams, user.TeamID.String)
	}
	if perm.Org != user.OrgID.String {
		t.Errorf("Org: got %q, want %q", perm.Org, user.OrgID.String)
	}
}
