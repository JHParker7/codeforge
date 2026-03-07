package routes

import (
	"codeforge/src/gatekeeper/auth"
	"codeforge/src/gatekeeper/database"
	"codeforge/src/gatekeeper/types"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func GetToken(c *gin.Context) {
	type TokenRequest struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	type TokenResponse struct {
		Token string `json:"token"`
	}

	var tokenRequest TokenRequest

	err := c.ShouldBindJSON(&tokenRequest)
	if err != nil {
		slog.Error(err.Error())
	}

	id, err := database.AuthUser(tokenRequest.Username, tokenRequest.Password)
	if err != nil {
		slog.Error(err.Error())
	}

	if id == "incorrect username or password" {

		var response types.APIResponse
		response.Code = 401
		response.Message = "incorrect username or password"

		c.JSON(http.StatusUnauthorized, response)
	}

	var session types.Session

	session.CreatedAt = time.Now()
	session.UpdatedAt = time.Now()
	session.UserID = id
	session.ExpiresAt = time.Now().Add(24 * time.Hour)

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	exp := jwt.NewNumericDate(session.ExpiresAt)
	token, err := auth.CreateJWT(database.GetUser(id), exp, privateKey)
	if err != nil {
		slog.Error(err.Error())
	}
	session.PubKey = publicKey
	session.Type = "jwt"
	session.Token = token
	UUID, err := uuid.NewV7()
	if err != nil {
		slog.Error("uuid for session failed error:", "error", err.Error())
	}
	session.ID = UUID.String()

	_, err = database.CreateSession(session)
	if err != nil {
		slog.Error("CreateSession Failed", "error", err.Error())
	}

	var Response TokenResponse
	Response.Token = token
	c.JSON(http.StatusOK, Response)
}
