package routes

import (
	"codeforge/src/gatekeeper/database"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GetUser(c *gin.Context) {
	type GetUserID struct {
		ID string `uri:"id" binding:"required,uuid"`
	}

	var getUserID GetUserID

	if err := c.ShouldBindUri(&getUserID); err != nil {
		c.JSON(400, gin.H{"msg": err.Error()})
		return
	}

	slog.Info(getUserID.ID)
	user := database.GetUser(getUserID.ID)
	slog.Info(user.ID)
	c.JSON(http.StatusOK, user)
}

func DeleteUser(c *gin.Context) {}

func PutUser(c *gin.Context) {}
