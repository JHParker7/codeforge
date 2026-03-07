package types

import (
	"database/sql"
	"time"
)

type User struct {
	ID        string         `json:"id"`
	Username  string         `json:"username"`
	Password  string         `json:"password"`
	Salt      string         `json:"salt"`
	Email     string         `json:"email"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	RoleID    sql.NullString `json:"role_id"`
	TeamID    sql.NullString `json:"team_id"`
	OrgID     sql.NullString `json:"org_id"`
	Active    bool           `json:"active"`
}

type Team struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Owner     string
	OrgID     string
}

type Org struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Role struct {
	ID          string    `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Permissions any       `json:"Permissions"`
}

type Service struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Name      string    `json:"name"`
	IconPath  string    `json:"icon_path"`
	Path      string    `json:"path"`
}

type Session struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"token"`
	Type      string    `json:"type"`
	UserID    string    `json:"user_id"`
	PubKey    []byte    `json:"pub_key"`
}

type Host struct {
	ID        string `json:"id"`
	Hostname  string
	IP        string
	Port      int32
	Service   string
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
