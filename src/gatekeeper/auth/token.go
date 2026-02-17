package auth

import (
	"codeforge/src/gatekeeper/types"
	"crypto/ed25519"
	"errors"
	"log"

	"github.com/golang-jwt/jwt/v5"
)

func CreateJWT(user types.User, exp jwt.NumericDate, privateKey ed25519.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"exp":        exp,
		"authorized": true,
		"username":   user.Username,
		"email":      user.Email,
		"id":         user.ID,
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return tokenString, nil
	}

	return tokenString, nil
}

func CheckJWT(token string, user types.User, pub ed25519.PublicKey) (types.JWTClaim, error) {
	var JWTClaim types.JWTClaim

	ParsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return pub, nil
	})

	claims := ParsedToken.Claims.(jwt.MapClaims)

	JWTClaim.Exp = claims["exp"].(float64)
	JWTClaim.Authorized = claims["authorized"].(bool)
	JWTClaim.Username = claims["username"].(string)
	JWTClaim.Email = claims["email"].(string)
	JWTClaim.ID = claims["id"].(string)

	if err != nil {
		return JWTClaim, err
	}

	if JWTClaim.Email != user.Email || JWTClaim.Username != user.Email || JWTClaim.ID != user.ID {
		log.Println("claim doesn't match user")
		JWTClaim.Authorized = false
		return JWTClaim, errors.New("claim doesn't match user")
	}
	return JWTClaim, nil
}
