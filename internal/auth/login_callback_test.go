package auth

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestConsumeLoginCallbackRejectsInvalidRequestsWithoutConsuming(t *testing.T) {
	const (
		browserToken = "test-browser-token"
		validQuery   = "state=login-state&code=auth-code"
	)
	validCookie := &http.Cookie{Name: loginCookieName, Value: browserToken}
	now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		query  string
		cookie *http.Cookie
	}{
		{"malformed query", validQuery + "&invalid=%zz", validCookie},
		{"provider error", validQuery + "&error=access_denied", validCookie},
		{"missing state", "code=auth-code", validCookie},
		{"empty state", "state=&code=auth-code", validCookie},
		{"duplicate state", validQuery + "&state=login-state", validCookie},
		{"unknown state", "state=unknown&code=auth-code", validCookie},
		{"missing code", "state=login-state", validCookie},
		{"empty code", "state=login-state&code=", validCookie},
		{"duplicate code", validQuery + "&code=other", validCookie},
		{"missing cookie", validQuery, nil},
		{"empty cookie", validQuery, &http.Cookie{Name: loginCookieName}},
		{"wrong browser", validQuery, &http.Cookie{Name: loginCookieName, Value: "wrong-browser"}},
		{"session cookie only", validQuery, &http.Cookie{Name: sessionCookieName, Value: browserToken}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemoryLoginAttempts()
			attempt := loginAttempt{state: "login-state", nonce: "login-nonce", codeVerifier: "login-verifier", expiresAt: now.Add(time.Minute)}
			store.save(attempt, sha256.Sum256([]byte(browserToken)), now.Add(-time.Second))

			bad := newLoginCallbackRequest(tc.query, tc.cookie)
			if got, code, ok := consumeLoginCallback(bad, store, now); ok || code != "" || got != (loginAttempt{}) {
				t.Fatal("an invalid callback must not return an attempt or code")
			}

			good := newLoginCallbackRequest(validQuery, validCookie)
			if got, code, ok := consumeLoginCallback(good, store, now); !ok || got != attempt || code != "auth-code" {
				t.Fatal("the invalid callback prevented the legitimate callback from succeeding")
			}
		})
	}
}

func TestConsumeLoginCallbackAcceptsMatchingRequestOnlyOnce(t *testing.T) {
	const browserToken = "test-browser-token"
	now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
	attempt := loginAttempt{state: "login-state", nonce: "login-nonce", codeVerifier: "login-verifier", expiresAt: now.Add(time.Minute)}
	store := newMemoryLoginAttempts()
	store.save(attempt, sha256.Sum256([]byte(browserToken)), now.Add(-time.Second))
	req := newLoginCallbackRequest("state=login-state&code=auth%2Bcode", &http.Cookie{Name: loginCookieName, Value: browserToken})

	got, code, ok := consumeLoginCallback(req, store, now)
	if !ok || got != attempt || code != "auth+code" {
		t.Fatal("matching callback did not return the original attempt and decoded code")
	}
	if _, _, ok := consumeLoginCallback(req, store, now); ok {
		t.Fatal("same callback was accepted twice")
	}
}

func TestConsumeLoginCallbackRejectsExpiredAttempt(t *testing.T) {
	const browserToken = "test-browser-token"
	now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
	store := newMemoryLoginAttempts()
	store.save(loginAttempt{state: "login-state", expiresAt: now}, sha256.Sum256([]byte(browserToken)), now.Add(-time.Second))
	req := newLoginCallbackRequest("state=login-state&code=auth-code", &http.Cookie{Name: loginCookieName, Value: browserToken})

	if got, code, ok := consumeLoginCallback(req, store, now); ok || code != "" || got != (loginAttempt{}) {
		t.Fatal("callback was accepted at the expiration boundary")
	}
}

func TestLoginCallbackIssuesSessionUsingTimeAfterAuthentication(t *testing.T) {
	const browserToken = "test-browser-token"
	requestAt := time.Date(2020, time.January, 2, 12, 0, 0, 0, time.UTC)
	authenticatedAt := requestAt.Add(30 * time.Second)
	wantExpiry := authenticatedAt.Add(8 * time.Hour)
	store := newMemoryLoginAttempts()
	attempt := loginAttempt{state: "login-state", expiresAt: requestAt.Add(time.Minute)}
	store.save(attempt, sha256.Sum256([]byte(browserToken)), requestAt)

	currentTime := requestAt
	clockReads := 0
	now := func() time.Time {
		clockReads++
		return currentTime
	}
	authenticate := func(context.Context, string, loginAttempt) (string, error) {
		currentTime = authenticatedAt
		return "alice", nil
	}
	var savedExpiry time.Time
	writer := sessionWriterFunc(func(_ context.Context, _ [32]byte, _ string, expiresAt time.Time) error {
		savedExpiry = expiresAt
		return nil
	})
	router := gin.New()
	router.GET(loginCallbackPath, loginCallbackHandler(store, authenticate, writer, now))
	req := newLoginCallbackRequest("state=login-state&code=auth-code", &http.Cookie{Name: loginCookieName, Value: browserToken})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if clockReads != 2 {
		t.Errorf("clock read %d times, want once before and once after authentication", clockReads)
	}
	if !savedExpiry.Equal(wantExpiry) {
		t.Errorf("stored expiration = %v, want %v", savedExpiry, wantExpiry)
	}
	if cookie := responseCookie(t, rec, sessionCookieName); !cookie.Expires.Equal(wantExpiry) {
		t.Errorf("cookie expiration = %v, want %v", cookie.Expires, wantExpiry)
	}
}

func newLoginCallbackRequest(rawQuery string, cookie *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	req.URL.RawQuery = rawQuery
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}
