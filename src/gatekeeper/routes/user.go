package routes

import (
	"codeforge/src/gatekeeper/auth"
	"codeforge/src/gatekeeper/database"
	"codeforge/src/gatekeeper/types"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// checkPermission fetches the authenticated user's role and verifies it grants
// action on service ("Gatekeeper/User/{id}"). Returns true if the check passes
// or if the authenticated user has no role assigned. Writes a 403 and returns
// false if the check fails.
func checkPermission(c *gin.Context, action, service string) bool {
	authenticatedUserID := c.GetString("user_id")
	if authenticatedUserID == "" {
		return true
	}
	authenticatedUser := database.GetUser(authenticatedUserID)
	if !authenticatedUser.RoleID.Valid || authenticatedUser.RoleID.String == "" {
		return true
	}
	role, err := database.GetRole(authenticatedUser.RoleID.String)
	if err != nil {
		slog.Error("failed to get role", "error", err.Error())
		c.JSON(http.StatusForbidden, types.APIResponse{Code: http.StatusForbidden, Message: "forbidden"})
		return false
	}
	if !auth.HasPermission(role, action, service) {
		c.JSON(http.StatusForbidden, types.APIResponse{Code: http.StatusForbidden, Message: "forbidden"})
		return false
	}
	return true
}

func GetUser(c *gin.Context) {
	type GetUserID struct {
		ID string `uri:"id" binding:"required,uuid"`
	}

	var params GetUserID
	if err := c.ShouldBindUri(&params); err != nil {
		c.JSON(http.StatusOK, types.APIResponse{Code: http.StatusOK, Message: "user not found"})
		return
	}

	if !checkPermission(c, "GetUser", fmt.Sprintf("Gatekeeper/User/%s", params.ID)) {
		return
	}

	slog.Info(params.ID)
	user := database.GetUser(params.ID)
	slog.Info(user.ID)
	c.JSON(http.StatusOK, user)
}

func DeleteUser(c *gin.Context) {
	type DeleteUserID struct {
		ID string `uri:"id" binding:"required,uuid"`
	}

	var params DeleteUserID
	if err := c.ShouldBindUri(&params); err != nil {
		c.JSON(http.StatusOK, types.APIResponse{Code: http.StatusOK, Message: "user not found"})
		return
	}

	if !checkPermission(c, "DeleteUser", fmt.Sprintf("Gatekeeper/User/%s", params.ID)) {
		return
	}

	if err := database.DeleteUser(params.ID); err != nil {
		slog.Error("failed to delete user", "error", err.Error())
		c.JSON(http.StatusOK, types.APIResponse{Code: http.StatusOK, Message: "user not found"})
		return
	}

	c.JSON(http.StatusOK, types.APIResponse{Code: http.StatusOK, Message: "user deleted"})
}

func PutUser(c *gin.Context) {
	type PutUserID struct {
		ID string `uri:"id" binding:"required,uuid"`
	}
	type UpdateRequest struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required"`
	}

	var params PutUserID
	if err := c.ShouldBindUri(&params); err != nil {
		c.JSON(http.StatusOK, types.APIResponse{Code: http.StatusOK, Message: "user not found"})
		return
	}

	var req UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		slog.Error(err.Error())
		c.JSON(http.StatusBadRequest, types.APIResponse{Code: http.StatusBadRequest, Message: "invalid request"})
		return
	}

	if !checkPermission(c, "PutUser", fmt.Sprintf("Gatekeeper/User/%s", params.ID)) {
		return
	}

	if err := database.UpdateUser(types.User{
		ID:        params.ID,
		Username:  req.Username,
		Email:     req.Email,
		UpdatedAt: time.Now(),
	}); err != nil {
		slog.Error("failed to update user", "error", err.Error())
		c.JSON(http.StatusOK, types.APIResponse{Code: http.StatusOK, Message: "user not found"})
		return
	}

	c.JSON(http.StatusOK, types.APIResponse{Code: http.StatusOK, Message: "user updated"})
}
