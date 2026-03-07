package database

import (
	"codeforge/src/gatekeeper/types"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"
)

func GetUser(id string) types.User {
	conn := ConnectDB("codeforge")
	var user types.User
	slog.Debug(id)
	err := conn.QueryRow(context.Background(), "select id, username, email, created_at, updated_at,role_id, team_id, org_id from auth.users where id=$1 and active=true", id).Scan(&user.ID, &user.Username, &user.Email, &user.CreatedAt, &user.UpdatedAt, &user.RoleID, &user.TeamID, &user.OrgID)
	if err != nil && err != pgx.ErrNoRows {
		fmt.Fprintf(os.Stderr, "QueryRow failed | GetUser | %v\n", err)
		os.Exit(1)
	}
	if err == pgx.ErrNoRows {
		slog.Info("no matching user in database", "id", id)
	}
	return user
}

func CreateUser(user types.User) (string, error) {
	var err error
	conn := ConnectDB("codeforge")

	var id string
	err = conn.QueryRow(context.Background(), "select id from auth.users where username=$1", user.Username).Scan(&id)
	if err != nil && err != pgx.ErrNoRows {
		log.Println("QueryRow failed")
		return "", err
	}

	if id != "" {
		return "username taken", nil
	}

	slog.Info(user.Email)

	err = conn.QueryRow(context.Background(), "select id from auth.users where email=$1", user.Email).Scan(&id)
	if err != nil && err != pgx.ErrNoRows {
		log.Println("QueryRow failed")
		return "", err
	}
	slog.Info("result: ", "result", id)
	slog.Info("user id:", "id", user.ID)

	if id != "" {
		return "email in use", nil
	}
	slog.Info("adding new user to db")
	_, err = conn.Exec(
		context.Background(),
		"INSERT INTO auth.users (id, username, password, salt, email, created_at, updated_at,role_id, team_id, org_id, active) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, $11)",
		user.ID, user.Username, user.Password, user.Salt, user.Email, user.CreatedAt, user.UpdatedAt, user.RoleID, user.TeamID, user.OrgID, user.Active)
	if err != nil {
		slog.Error(err.Error())
	}

	err = conn.Close(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	return user.ID, nil
}

func AuthUser(Username string, Password string) (string, error) {
	var err error

	conn := ConnectDB("codeforge")

	var Salt string
	var id string

	err = conn.QueryRow(context.Background(), "select salt from auth.users where username=$1", Username).Scan(&Salt)
	if err != nil && err != pgx.ErrNoRows {
		log.Println("QueryRow failed get user via username | AuthUser | ")
		return "", err
	}

	PasswordHash := hex.EncodeToString(argon2.IDKey([]byte(Password), []byte(Salt), 1, 64*1024, 4, 32)[:])

	err = conn.QueryRow(context.Background(), "select id from auth.users where username=$1 and password=$2", Username, PasswordHash).Scan(&id)
	if err != nil && err != pgx.ErrNoRows {
		log.Println("QueryRow failed check username and password | AuthUser")
		return "", err
	}

	if id == "" {
		return "incorrect username or password", nil
	}

	return id, nil
}
