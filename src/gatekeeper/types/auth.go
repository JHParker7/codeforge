// Package types contains the types for gatekeeper
package types

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

type JWTClaim struct {
	Exp        float64
	Authorized bool
	Username   string
	Email      string
	ID         string
}
