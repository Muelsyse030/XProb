package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"example.com/xprob/internal/auth"
	"example.com/xprob/internal/monitor/repo"
	"github.com/gin-gonic/gin"
)

func TestHealth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body status = %q, want ok", body["status"])
	}
}

func TestHealthRejectsPost(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec := httptest.NewRecorder()
	newTestRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

func TestConfigureAuthWithInMemoryStorage(t *testing.T) {
	t.Setenv("XPROB_MYSQL_ADDR", "")
	monitors, store, err := openRepositories()
	if err != nil || monitors == nil || store != nil {
		t.Fatalf("expected a monitor repository and no auth store in memory mode, got error %v", err)
	}

	cases := []struct {
		name                             string
		issuer, clientID, secret, origin string
		wantError                        string
	}{
		{name: "not configured"},
		{
			name: "partially configured", issuer: "https://issuer.example",
			wantError: "all XPROB_OIDC_* values and XPROB_PUBLIC_ORIGIN must be configured together",
		},
		{
			name: "configured", issuer: "https://issuer.example", clientID: "xprob",
			secret: "test-secret", origin: testOrigin,
			wantError: "OIDC requires the MySQL session and workspace membership store",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XPROB_OIDC_ISSUER", tc.issuer)
			t.Setenv("XPROB_OIDC_CLIENT_ID", tc.clientID)
			t.Setenv("XPROB_OIDC_CLIENT_SECRET", tc.secret)
			t.Setenv("XPROB_PUBLIC_ORIGIN", tc.origin)

			access, err := configureAuth(t.Context(), store)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("configureAuth returned %v, want no error", err)
				}
			} else if err == nil || err.Error() != tc.wantError {
				t.Fatalf("configureAuth returned %v, want %q", err, tc.wantError)
			}
			if access != (routerAuth{}) {
				t.Error("authentication must not be enabled without an auth store")
			}
		})
	}
}

func newTestRouter() *gin.Engine {
	return newRouter(repo.NewMemory(), routerAuth{
		origin: testOrigin,
		sessions: sessionLookupFunc(func(_ context.Context, hash [32]byte) (string, error) {
			if hash != sha256.Sum256([]byte(testSessionToken)) {
				return "", auth.ErrInvalidSession
			}
			return "test-user", nil
		}),
		roles: roleLookupFunc(func(context.Context, string, string) (auth.Role, error) {
			return auth.RoleMaintainer, nil
		}),
	})
}

const (
	testOrigin       = "https://xprob.example"
	testSessionToken = "test-monitor-session"
)

func newMonitorTestRequest(method, path string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.AddCookie(&http.Cookie{Name: "xprob_session", Value: testSessionToken})
	req.Header.Set("Origin", testOrigin)
	return req
}
