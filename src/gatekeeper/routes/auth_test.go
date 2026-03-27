package routes

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// skipIfNoDB skips the test if DATABASE_URL is not set.
func skipIfNoDB(t *testing.T) {
	t.Helper()
	if os.Getenv("DATABASE_URL") == "" {
		t.Skip("DATABASE_URL not set")
	}
}

// TestAuthenticate_NoAuthorizationHeader verifies that when no Authorization
// header is present, Authenticate neither aborts nor writes a response —
// Gin's handler chain continues and the downstream handler is reached.
// (Authenticate only calls c.Abort() inside the "Bearer: " branch; without
// that branch executing there is no abort.)
func TestAuthenticate_NoAuthorizationHeader(t *testing.T) {
	handlerCalled := false
	r := gin.New()
	r.GET("/test", Authenticate, func(c *gin.Context) {
		handlerCalled = true
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if !handlerCalled {
		t.Error("expected downstream handler to be reached: Authenticate does not abort on missing header")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 from downstream handler, got %d", w.Code)
	}
}

// TestAuthenticate_InvalidBearerPrefix verifies the same fall-through
// behaviour for Authorization headers that do not contain "Bearer: ".
func TestAuthenticate_InvalidBearerPrefix(t *testing.T) {
	for _, header := range []string{"Token abc", "Bearer abc", "Basic xyz"} {
		t.Run(header, func(t *testing.T) {
			handlerCalled := false
			r := gin.New()
			r.GET("/test", Authenticate, func(c *gin.Context) {
				handlerCalled = true
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", header)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if !handlerCalled {
				t.Errorf("expected downstream handler to be reached for Authorization: %q", header)
			}
		})
	}
}

// TestAuthenticate_TokenNotInDB verifies the middleware returns 401 when the
// token is correctly prefixed but does not match any session in the database.
func TestAuthenticate_TokenNotInDB(t *testing.T) {
	skipIfNoDB(t)

	r := gin.New()
	r.GET("/test", Authenticate, func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer: unit_test_no_such_token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
