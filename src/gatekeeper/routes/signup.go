package routes

import (
	"codeforge/src/gatekeeper/auth"
	"codeforge/src/gatekeeper/database"
	"codeforge/src/gatekeeper/types"
	"database/sql"
	"encoding/hex"
	"log"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

func PostUser(c *gin.Context) {
	type UserRequest struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		Email    string `json:"email" binding:"required"`
	}

	type TokenResponse struct {
		Reason      string `json:"reason"`
		UserCreated bool   `json:"user_created"`
	}

	var userRequest UserRequest
	var newUser types.User

	err := c.ShouldBindJSON(&userRequest)
	if err != nil {
		log.Fatal(err)
	}

	newUser.Email = userRequest.Email
	newUser.Username = userRequest.Username
	newUser.Active = true

	newUser.Salt, err = generateRandomString(64)
	errorHandler(err)

	newUser.Password = hex.EncodeToString(argon2.IDKey([]byte(userRequest.Password), []byte(newUser.Salt), 1, 64*1024, 4, 32)[:])

	user_UUID, err := uuid.NewV7()
	if err != nil {
		slog.Error("uuid generation for user failed error:", "error", err.Error())
	}

	newUser.ID = user_UUID.String()

	role := auth.CreateEmptyUserRole(newUser)

	// Create the role first; users.role_id is a FK to roles.id so the role
	// must exist before the user row references it.
	_, err = database.CreateRole(role)
	if err != nil {
		slog.Error("failed to add role to database:", "error", err.Error())
	} else {
		newUser.RoleID = sql.NullString{String: role.ID, Valid: true}
	}

	userResponse, err := database.CreateUser(newUser)
	if err != nil {
		slog.Error("failed to add user to database:", "error", err.Error())
	}

	var response TokenResponse
	response.Reason = userResponse

	if userResponse == "username taken" || userResponse == "email in use" {
		response.Reason = userResponse
		response.UserCreated = false
		c.JSON(http.StatusOK, response)
		return
	}

	response.Reason = "user created"
	response.UserCreated = true
	c.JSON(http.StatusOK, response)
}
