package routes

import (
	"codeforge/src/gatekeeper/auth"
	"codeforge/src/gatekeeper/database"
	"codeforge/src/gatekeeper/types"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func CheckCookie(cookie string) {
}

func bytesToEd25519PublicKey(pubBytes []byte) (ed25519.PublicKey, error) {
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key length")
	}
	return pubBytes, nil
}

func Authenticate(c *gin.Context) {
	var failResponse types.APIResponse

	failResponse.Code = http.StatusUnauthorized
	failResponse.Message = "invaild token"
	cookie, err := c.Cookie("gin_cookie")
	if err != nil {
		slog.Info("failed to get cookie", "error", err.Error())
	}
	token := c.GetHeader("Authorization")
	if cookie != "" {
	}
	if strings.Contains(token, "Bearer: ") {
		token = strings.TrimPrefix(token, "Bearer: ")

		session, err := database.GetSession(token)
		if err != nil {
			slog.Error("failed to get session", "error", err.Error())
			c.JSON(http.StatusUnauthorized, failResponse)
			c.Abort()
			return
		}
		user := database.GetUser(session.UserID)
		pubKey, err := bytesToEd25519PublicKey(session.PubKey)
		if err != nil {
			slog.Error("failed to create public key from bytes", "error", err.Error())
			c.JSON(http.StatusUnauthorized, failResponse)
			c.Abort()
			return
		}

		claims, err := auth.CheckJWT(token, user, pubKey)
		if err != nil {
			slog.Error("failed to check JWT", "error", err.Error())
			c.JSON(http.StatusUnauthorized, failResponse)
			c.Abort()
			return
		}
		slog.Info("", "Authorized", claims.Authorized)
		if claims.Authorized {
			c.Set("user_id", claims.ID)
			c.Next()
			return
		} else {
			c.JSON(http.StatusUnauthorized, failResponse)
			c.Abort()
			return
		}
	}
}
