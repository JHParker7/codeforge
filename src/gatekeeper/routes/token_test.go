package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGetToken_CorrectCredentials(t *testing.T) {
	skipIfNoDB(t)

	r := gin.New()
	r.GET("/token", GetToken)

	body := `{"username":"test","password":"test"}`
	req := httptest.NewRequest(http.MethodGet, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	token, ok := resp["token"]
	if !ok {
		t.Fatal("response is missing 'token' field")
	}
	if token == "" {
		t.Error("expected non-empty token value")
	}
}

// TestGetToken_WrongPassword verifies that a bad password yields a 401.
// Note: due to a missing return after the 401 write in GetToken, the handler
// continues execution and appends a second JSON object to the body. The status
// code is still 401 because net/http ignores subsequent WriteHeader calls.
func TestGetToken_WrongPassword(t *testing.T) {
	skipIfNoDB(t)

	r := gin.New()
	r.GET("/token", GetToken)

	body := `{"username":"test","password":"wrongpassword"}`
	req := httptest.NewRequest(http.MethodGet, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestGetToken_NonExistentUser(t *testing.T) {
	skipIfNoDB(t)

	r := gin.New()
	r.GET("/token", GetToken)

	body := `{"username":"unit_test_no_such_user","password":"anypass"}`
	req := httptest.NewRequest(http.MethodGet, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
