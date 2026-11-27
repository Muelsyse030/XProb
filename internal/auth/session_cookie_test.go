package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSetSessionCookie(t *testing.T) {
	token, _ := newSessionToken()
	expiresAt := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, token, expiresAt)
	resp := rec.Result()
	defer resp.Body.Close()

	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != sessionCookieName {
		t.Errorf("cookie name = %q, want %q", cookie.Name, sessionCookieName)
	}
	if token == "" || cookie.Value != token {
		t.Error("cookie value must match the original session token")
	}
	if cookie.Path != "/" || cookie.Domain != "" {
		t.Errorf("cookie path = %q, domain = %q; want root path and no Domain attribute", cookie.Path, cookie.Domain)
	}
	if !cookie.Expires.Equal(expiresAt) {
		t.Errorf("cookie expires = %s, want %s", cookie.Expires, expiresAt.UTC())
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie flags: HttpOnly=%t, Secure=%t, SameSite=%v; want HttpOnly, Secure, and Lax",
			cookie.HttpOnly, cookie.Secure, cookie.SameSite)
	}
}
