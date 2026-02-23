package routes

import (
	"codeforge/src/gatekeeper/database"
	"codeforge/src/gatekeeper/types"
	"encoding/hex"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

func PutUser(c *gin.Context) {
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

	hash, err := uuid.NewV7()
	if err != nil {
		log.Fatal("uuid failed to generate")
	}

	newUser.ID = hash.String()

	userResponse, err := database.CreateUser(newUser)

	var response TokenResponse
	response.Reason = userResponse

	if userResponse == "username taken" || userResponse == "email in use" {
		response.Reason = userResponse
		response.UserCreated = false
		c.JSON(http.StatusOK, response)
	} else {
		response.Reason = "user created"
		response.UserCreated = true
		c.JSON(http.StatusOK, response)

	}
}
