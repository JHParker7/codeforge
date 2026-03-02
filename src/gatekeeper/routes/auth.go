package routes

import (
	"codeforge/src/gatekeeper/auth"
	"net/http"

	"github.com/gin-gonic/gin"
)

func CheckCookie(cookie string) {
}

func Authenticate(c *gin.Context) {
	cookie, err := c.Cookie("gin_cookie")
	if err != nil {
		jwt := c.GetHeader("Authorization")
		if jwt != "" {
			auth.CheckJWT(jwt, user types.User, pub ed25519.PublicKey)
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "no token detected"})
		}
	} else {
		CheckCookie(cookie)
	}
}
