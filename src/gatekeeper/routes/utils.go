package routes

import (
	"crypto/rand"
	"encoding/base64"
	"log"
)

func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

func errorHandler(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
