package database

import (
	"codeforge/src/gatekeeper/types"
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5"
)

func GetUser(id string) types.User {
	conn := ConnectDB("codeforge")
	var user types.User
	err := conn.QueryRow(context.Background(), "select *  from auth.users where id = $1", id).Scan(&user)
	if err != nil && err != pgx.ErrNoRows {
		fmt.Fprintf(os.Stderr, "QueryRow failed: %v\n", err)
		os.Exit(1)
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
