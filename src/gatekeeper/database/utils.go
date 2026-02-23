package database

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

func ConnectDB(DatabaseName string) pgx.Conn {
	conn, err := pgx.Connect(context.Background(), os.Getenv("DATABASE_URL")+"/"+DatabaseName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to connect to database: %v\n", err)
		os.Exit(1)
	}
	// defer conn.Close(context.Background())
	return *conn
}
