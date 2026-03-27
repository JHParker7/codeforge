package auth

import (
	"codeforge/src/gatekeeper/types"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// HasPermission reports whether role grants action on service.
// service should be of the form "Gatekeeper/User/{id}".
func HasPermission(role types.Role, action string, service string) bool {
	perms, ok := role.Permissions.(types.Permissions)
	if !ok {
		return false
	}
	for _, perm := range perms.Permissions {
		actionFound := false
		for _, a := range perm.Actions {
			if a == action {
				actionFound = true
				break
			}
		}
		if !actionFound {
			continue
		}
		for _, s := range perm.Services {
			if s == service {
				return true
			}
		}
	}
	return false
}

func CreateEmptyUserRole(user types.User) types.Role {
	var OwnUserPermission types.Permission

	OwnUserPermission.Services = []string{fmt.Sprintf("Gatekeeper/User/%s", user.ID)}
	OwnUserPermission.Actions = []string{"DeleteUser", "GetUser", "PutUser"}
	OwnUserPermission.Teams = []string{user.TeamID.String}
	OwnUserPermission.Org = user.OrgID.String

	var OwnUserPermissions types.Permissions

	OwnUserPermissions.Permissions = []types.Permission{OwnUserPermission}
	OwnUserPermissions.Valid = true

	var OwnUserRole types.Role

	OwnUserRole.Permissions = OwnUserPermissions
	OwnUserRole.CreatedAt = time.Now()
	OwnUserRole.CreatedAt = time.Now()

	role_UUID, err := uuid.NewV7()
	if err != nil {
		slog.Error("uuid generation for user failed error:", "error", err.Error())
	}

	OwnUserRole.ID = role_UUID.String()

	return OwnUserRole
}
