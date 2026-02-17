package auth

import (
	"codeforge/src/gatekeeper/types"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestTemp(t *testing.T) {
	var TestUser types.User

	privateKeyPEM, _ := os.ReadFile("private.pem")
	block, _ := pem.Decode(privateKeyPEM)
	privKey, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	priv := privKey.(ed25519.PrivateKey)

	// TestUuid, _ := uuid.NewV7()

	TestTime := time.Date(2026, time.February, 10, 10, 10, 10, 10, time.UTC)

	TestUser.Active = true
	TestUser.CreatedAt = TestTime
	TestUser.UpdatedAt = TestTime
	TestUser.Email = "test@test.com"
	TestUser.ID = "019c5df7-7e21-73fd-9641-d0e9208a927e"
	TestUser.Username = "test"

	var TestExp jwt.NumericDate

	TestExp.Time = TestTime.Add(30 * time.Minute)

	token, err := CreateJWT(TestUser, TestExp, priv)
	if err != nil {
		log.Println("error is not nil")
		t.Fail()
	}

	if token != "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkIjp0cnVlLCJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJleHAiOjE3NzA3MjAwMTAsImlkIjoiMDE5YzVkZjctN2UyMS03M2ZkLTk2NDEtZDBlOTIwOGE5MjdlIiwidXNlcm5hbWUiOiJ0ZXN0In0.P89qxi7tp7Opzw2S0-2LkbTUQ-Aredb4KjtjGn7R-oPi8bte1ArSnMdaG7IljIM8onsI5rGHyyfp1IBG9sUWCQ" {
		log.Println("jwt is wrong:")
		log.Println(token)
		t.Fail()
	}
	ParsedToken, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return priv.Public(), nil
	})

	if ParsedToken.Valid != false {
		log.Println("token should be expired")
		t.Fail()
	}

	token, err = CreateJWT(TestUser, TestExp, priv)
	if err != nil {
		log.Println("error is not nil")
		t.Fail()
	}

	ParsedToken, err = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return priv.Public(), nil
	})
	if err != nil {
		log.Println(err)
		log.Println("token not vaild")

	}

	claims := ParsedToken.Claims.(jwt.MapClaims)

	exp := claims["exp"].(float64)
	authorized := claims["authorized"].(bool)
	username := claims["username"].(string)
	email := claims["email"].(string)
	id := claims["id"].(string)

	if exp != float64(TestExp.Unix()) {
		println("exp is wrong")
		t.Fail()
	}
	if authorized != true {
		println("claim not authorized")
		t.Fail()
	}
	if username != "test" {
		println("username is wrong")
		t.Fail()
	}
	if email != "test@test.com" {
		println("email is wrong")
		t.Fail()
	}
	if id != TestUser.ID {
		println("id is wrong")
	}
}

func TestCheckJWT(t *testing.T) {
	TestToken := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhdXRob3JpemVkIjp0cnVlLCJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJleHAiOjE3NzA3MjAwMTAsImlkIjoiMDE5YzVkZjctN2UyMS03M2ZkLTk2NDEtZDBlOTIwOGE5MjdlIiwidXNlcm5hbWUiOiJ0ZXN0In0.P89qxi7tp7Opzw2S0-2LkbTUQ-Aredb4KjtjGn7R-oPi8bte1ArSnMdaG7IljIM8onsI5rGHyyfp1IBG9sUWCQ"

	privateKeyPEM, _ := os.ReadFile("private.pem")
	block, _ := pem.Decode(privateKeyPEM)
	privKey, _ := x509.ParsePKCS8PrivateKey(block.Bytes)
	priv := privKey.(ed25519.PrivateKey)

	var TestUser types.User

	TestTime := time.Date(2026, time.February, 10, 10, 10, 10, 10, time.UTC)

	TestUser.Active = true
	TestUser.CreatedAt = TestTime
	TestUser.UpdatedAt = TestTime
	TestUser.Email = "test@test.com"
	TestUser.ID = "019c5df7-7e21-73fd-9641-d0e9208a927e"
	TestUser.Username = "test"

	var TestExp jwt.NumericDate

	TestExp.Time = TestTime.Add(30 * time.Minute)

	Claim, err := CheckJWT(TestToken, TestUser, priv)
	if err == nil {
		println("token should be expired")
		t.Fail()
	}

	if Claim.Exp != float64(TestExp.Unix()) {
		println("exp is wrong:")
		println(Claim.Exp)
		println(float64(TestExp.Unix()))
		t.Fail()
	}
	if Claim.Authorized != true {
		println("claim not authorized")
		t.Fail()
	}
	if Claim.Username != "test" {
		println("username is wrong")
		t.Fail()
	}
	if Claim.Email != "test@test.com" {
		println("email is wrong")
		t.Fail()
	}
	if Claim.ID != TestUser.ID {
		println("id is wrong")
	}

	TestUser.Username = "test1"

	Claim, err = CheckJWT(TestToken, TestUser, priv)
	if err != errors.New("claim doesn't match user") && Claim.Authorized != false {
		println("claim should be invalid")
	}

	TestUser.Email = "fail@test.com"

	Claim, err = CheckJWT(TestToken, TestUser, priv)
	if err != errors.New("claim doesn't match user") && Claim.Authorized != false {
		println("claim should be invalid")
	}

	TestUser.ID = "test"

	Claim, err = CheckJWT(TestToken, TestUser, priv)
	if err != errors.New("claim doesn't match user") && Claim.Authorized != false {
		println("claim should be invalid")
	}
}
