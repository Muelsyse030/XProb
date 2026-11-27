package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type sessionReaderFunc func(context.Context, [32]byte) (string, error)

func (f sessionReaderFunc) FindUserBySession(ctx context.Context, tokenHash [32]byte) (string, error) {
	return f(ctx, tokenHash)
}

func TestRequireSession(t *testing.T) {
	const token = "opaque-test-token"
	cases := []struct {
		name        string
		cookie      *http.Cookie
		userID      string
		lookupErr   error
		wantStatus  int
		wantLookups int
	}{
		{name: "missing cookie", wantStatus: http.StatusUnauthorized},
		{name: "empty cookie", cookie: &http.Cookie{Name: sessionCookieName}, wantStatus: http.StatusUnauthorized},
		{name: "invalid session", cookie: &http.Cookie{Name: sessionCookieName, Value: token},
			lookupErr: fmt.Errorf("lookup: %w", ErrInvalidSession), wantStatus: http.StatusUnauthorized, wantLookups: 1},
		{name: "lookup failure", cookie: &http.Cookie{Name: sessionCookieName, Value: token},
			lookupErr: errors.New("database unavailable"), wantStatus: http.StatusInternalServerError, wantLookups: 1},
		{name: "missing user ID in lookup result", cookie: &http.Cookie{Name: sessionCookieName, Value: token},
			wantStatus: http.StatusInternalServerError, wantLookups: 1},
		{name: "valid session", cookie: &http.Cookie{Name: sessionCookieName, Value: token},
			userID: "alice", wantStatus: http.StatusNoContent, wantLookups: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookups := 0
			reader := sessionReaderFunc(func(_ context.Context, hash [32]byte) (string, error) {
				lookups++
				if want := sha256.Sum256([]byte(token)); hash != want {
					t.Errorf("FindUserBySession hash = %x, want %x", hash, want)
				}
				return tc.userID, tc.lookupErr
			})

			handlerRan := false
			router := gin.New()
			router.GET("/monitors", RequireSession(reader), func(c *gin.Context) {
				handlerRan = true
				if userID, ok := SessionUserID(c); !ok || userID != tc.userID {
					t.Errorf("SessionUserID = (%q, %t), want (%q, true)", userID, ok, tc.userID)
				}
				c.Status(http.StatusNoContent)
			})

			req := httptest.NewRequest(http.MethodGet, "/monitors", nil)
			req.Header.Set("X-User-ID", "someone-else")
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if lookups != tc.wantLookups {
				t.Errorf("session lookups = %d, want %d", lookups, tc.wantLookups)
			}
			if want := tc.wantStatus == http.StatusNoContent; handlerRan != want {
				t.Errorf("handlerRan = %t, want %t", handlerRan, want)
			}
		})
	}
}
