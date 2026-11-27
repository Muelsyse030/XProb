package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewSessionToken(t *testing.T) {
	token, hash := newSessionToken()
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal("token is not unpadded URL-safe Base64")
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded token has %d bytes, want 32", len(decoded))
	}
	if hash != sha256.Sum256([]byte(token)) {
		t.Error("returned hash does not match the SHA-256 of the cookie token")
	}
}

func TestGeneratedSessionTokenWorksWithRequireSession(t *testing.T) {
	token, storedHash := newSessionToken()
	reader := sessionReaderFunc(func(_ context.Context, lookupHash [32]byte) (string, error) {
		if lookupHash != storedHash {
			return "", ErrInvalidSession
		}
		return "alice", nil
	})

	router := gin.New()
	router.GET("/monitors", RequireSession(reader), func(c *gin.Context) {
		if userID, ok := SessionUserID(c); !ok || userID != "alice" {
			t.Errorf("SessionUserID = (%q, %t), want (alice, true)", userID, ok)
		}
		c.Status(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/monitors", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}
