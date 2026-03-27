package routes

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// jwtUserID decodes the JWT payload (no verification) and returns the "id" claim.
func jwtUserID(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected JWT format: %q", token)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode JWT payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(b, &claims); err != nil {
		t.Fatalf("failed to unmarshal JWT claims: %v", err)
	}
	id, _ := claims["id"].(string)
	return id
}

// signupAndToken creates a user via the signup endpoint and returns their JWT.
func signupAndToken(t *testing.T, r *gin.Engine, username, password string) string {
	t.Helper()

	signupBody := `{"username":"` + username + `","password":"` + password + `","email":"` + username + `@t.l"}`
	req := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(signupBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("signup failed: %d %s", w.Code, w.Body.String())
	}

	tokenBody := `{"username":"` + username + `","password":"` + password + `"}`
	req = httptest.NewRequest(http.MethodGet, "/token", strings.NewReader(tokenBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("token request failed: %d %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	token, _ := resp["token"].(string)
	return token
}

// TestGetUser_InvalidUUID verifies that a non-UUID path parameter returns a
// "user not found" response without reaching the database.
func TestGetUser_InvalidUUID(t *testing.T) {
	r := gin.New()
	r.GET("/user/:id", GetUser)

	req := httptest.NewRequest(http.MethodGet, "/user/not-a-uuid", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if resp["message"] != "user not found" {
		t.Errorf("message: got %v, want %q", resp["message"], "user not found")
	}
}

// TestGetUser_OwnResourceAllowed verifies that a signed-up user (who has a
// role created and linked by the signup endpoint) can fetch their own record.
func TestGetUser_OwnResourceAllowed(t *testing.T) {
	skipIfNoDB(t)

	r := gin.New()
	r.POST("/signup", PostUser)
	r.GET("/token", GetToken)
	r.GET("/user/:id", Authenticate, GetUser)

	username := "perm_own_" + strings.ReplaceAll(t.Name(), "/", "_")
	token := signupAndToken(t, r, username, "testpass")
	userID := jwtUserID(t, token)

	req := httptest.NewRequest(http.MethodGet, "/user/"+userID, nil)
	req.Header.Set("Authorization", "Bearer: "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 fetching own resource, got %d: %s", w.Code, w.Body.String())
	}
}

// TestGetUser_OtherResourceForbidden verifies that a user whose role only
// covers their own resource gets 403 when requesting a different user's record.
func TestGetUser_OtherResourceForbidden(t *testing.T) {
	skipIfNoDB(t)

	r := gin.New()
	r.POST("/signup", PostUser)
	r.GET("/token", GetToken)
	r.GET("/user/:id", Authenticate, GetUser)

	username := "perm_other_" + strings.ReplaceAll(t.Name(), "/", "_")
	token := signupAndToken(t, r, username, "testpass")

	// Attempt to fetch the seed user's record — a different user.
	req := httptest.NewRequest(http.MethodGet, "/user/019cc784-cd17-7d02-8312-31175e7cf926", nil)
	req.Header.Set("Authorization", "Bearer: "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 fetching another user's resource, got %d: %s", w.Code, w.Body.String())
	}
}

// --- DeleteUser ---

func TestDeleteUser_InvalidUUID(t *testing.T) {
	r := gin.New()
	r.DELETE("/user/:id", DeleteUser)

	req := httptest.NewRequest(http.MethodDelete, "/user/not-a-uuid", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["message"] != "user not found" {
		t.Errorf("message: got %v, want %q", resp["message"], "user not found")
	}
}

func TestDeleteUser_OwnResourceAllowed(t *testing.T) {
	skipIfNoDB(t)

	r := gin.New()
	r.POST("/signup", PostUser)
	r.GET("/token", GetToken)
	r.DELETE("/user/:id", Authenticate, DeleteUser)

	username := "del_own_" + strings.ReplaceAll(t.Name(), "/", "_")
	token := signupAndToken(t, r, username, "testpass")
	userID := jwtUserID(t, token)

	req := httptest.NewRequest(http.MethodDelete, "/user/"+userID, nil)
	req.Header.Set("Authorization", "Bearer: "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["message"] != "user deleted" {
		t.Errorf("message: got %v, want %q", resp["message"], "user deleted")
	}
}

func TestDeleteUser_OtherResourceForbidden(t *testing.T) {
	skipIfNoDB(t)

	r := gin.New()
	r.POST("/signup", PostUser)
	r.GET("/token", GetToken)
	r.DELETE("/user/:id", Authenticate, DeleteUser)

	username := "del_other_" + strings.ReplaceAll(t.Name(), "/", "_")
	token := signupAndToken(t, r, username, "testpass")

	req := httptest.NewRequest(http.MethodDelete, "/user/019cc784-cd17-7d02-8312-31175e7cf926", nil)
	req.Header.Set("Authorization", "Bearer: "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// --- PutUser ---

func TestPutUser_InvalidUUID(t *testing.T) {
	r := gin.New()
	r.PUT("/user/:id", PutUser)

	body := `{"username":"newname","email":"new@t.l"}`
	req := httptest.NewRequest(http.MethodPut, "/user/not-a-uuid", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["message"] != "user not found" {
		t.Errorf("message: got %v, want %q", resp["message"], "user not found")
	}
}

func TestPutUser_MissingFields(t *testing.T) {
	r := gin.New()
	r.PUT("/user/:id", PutUser)

	req := httptest.NewRequest(http.MethodPut, "/user/019cc784-cd17-7d02-8312-31175e7cf926", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestPutUser_OwnResourceAllowed(t *testing.T) {
	skipIfNoDB(t)

	r := gin.New()
	r.POST("/signup", PostUser)
	r.GET("/token", GetToken)
	r.PUT("/user/:id", Authenticate, PutUser)
	r.GET("/user/:id", Authenticate, GetUser)

	username := "put_own_" + strings.ReplaceAll(t.Name(), "/", "_")
	token := signupAndToken(t, r, username, "testpass")
	userID := jwtUserID(t, token)

	newUsername := username + "_upd"
	newEmail := newUsername + "@t.l"
	body := `{"username":"` + newUsername + `","email":"` + newEmail + `"}`
	req := httptest.NewRequest(http.MethodPut, "/user/"+userID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer: "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["message"] != "user updated" {
		t.Errorf("message: got %v, want %q", resp["message"], "user updated")
	}

	// Re-authenticate with the new username to get a fresh token, then verify
	newToken := signupAndToken_tokenOnly(t, r, newUsername, "testpass")
	req = httptest.NewRequest(http.MethodGet, "/user/"+userID, nil)
	req.Header.Set("Authorization", "Bearer: "+newToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on verify, got %d: %s", w.Code, w.Body.String())
	}
	var user map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &user)
	if user["username"] != newUsername {
		t.Errorf("username after update: got %v, want %q", user["username"], newUsername)
	}
	if user["email"] != newEmail {
		t.Errorf("email after update: got %v, want %q", user["email"], newEmail)
	}
}

func TestPutUser_OtherResourceForbidden(t *testing.T) {
	skipIfNoDB(t)

	r := gin.New()
	r.POST("/signup", PostUser)
	r.GET("/token", GetToken)
	r.PUT("/user/:id", Authenticate, PutUser)

	username := "put_other_" + strings.ReplaceAll(t.Name(), "/", "_")
	token := signupAndToken(t, r, username, "testpass")

	body := `{"username":"hacked","email":"hacked@t.l"}`
	req := httptest.NewRequest(http.MethodPut, "/user/019cc784-cd17-7d02-8312-31175e7cf926", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer: "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// signupAndToken_tokenOnly fetches a token without signing up (user already exists).
func signupAndToken_tokenOnly(t *testing.T, r *gin.Engine, username, password string) string {
	t.Helper()
	tokenBody := `{"username":"` + username + `","password":"` + password + `"}`
	req := httptest.NewRequest(http.MethodGet, "/token", strings.NewReader(tokenBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("token request failed: %d %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	token, _ := resp["token"].(string)
	return token
}

// TestGetUser_NonExistentUUID verifies that a valid-format UUID that does not
// exist in the database returns an empty user body (no DB error).
func TestGetUser_NonExistentUUID(t *testing.T) {
	skipIfNoDB(t)

	r := gin.New()
	r.GET("/user/:id", GetUser)

	req := httptest.NewRequest(http.MethodGet, "/user/00000000-0000-0000-0000-000000000000", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if resp["id"] != "" {
		t.Errorf("expected empty id for nonexistent user, got %v", resp["id"])
	}
}
