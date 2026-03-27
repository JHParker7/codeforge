package types

type Permission struct {
	Actions  []string `json:"actions"`
	Services []string `json:"services"`
	Teams    []string `json:"teams"`
	Org      string   `json:"org"`
}

type Permissions struct {
	Valid       bool         `json:"valid"`
	Permissions []Permission `json:"permissions"`
}
