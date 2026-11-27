package auth

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestStartLoginRedirectsAndBindsAttemptToBrowser(t *testing.T) {
	now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
	store := newMemoryLoginAttempts()
	cfg := loginConfig{
		authorizationEndpoint: "https://idp.example/authorize",
		clientID:              "xprob-client",
		redirectURI:           "https://xprob.example/auth/callback",
	}
	router := gin.New()
	router.GET("/auth/login", startLoginHandler(store, cfg, func() time.Time { return now }))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	resp := rec.Result()
	defer resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	target, err := resp.Location()
	if err != nil || target.Scheme != "https" || target.Host != "idp.example" || target.Path != "/authorize" {
		t.Fatal("redirect did not target the configured authorization endpoint")
	}
	query, err := url.ParseQuery(target.RawQuery)
	if err != nil {
		t.Fatal("redirect contains an invalid query")
	}
	if query.Get("client_id") != cfg.clientID || query.Get("redirect_uri") != cfg.redirectURI {
		t.Error("redirect does not contain the configured client ID and callback")
	}
	state := query.Get("state")
	if state == "" {
		t.Fatal("redirect is missing the login state")
	}

	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want exactly one temporary login cookie", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != loginCookieName || cookie.Value == "" || cookie.Value == state {
		t.Fatal("temporary cookie did not contain a separate browser token")
	}
	if cookie.Path != "/auth/callback" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Error("temporary cookie must be host-only, callback-scoped, Secure, HttpOnly and SameSite=Lax")
	}
	if !cookie.Expires.Equal(now.Add(5 * time.Minute)) {
		t.Errorf("cookie expires at %s, want %s", cookie.Expires, now.Add(5*time.Minute))
	}

	wrongHash := sha256.Sum256([]byte("different-browser-token"))
	if _, ok := store.consume(state, wrongHash, now); ok {
		t.Fatal("another browser was able to consume the saved attempt")
	}
	browserHash := sha256.Sum256([]byte(cookie.Value))
	attempt, ok := store.consume(state, browserHash, now)
	if !ok || attempt.state != state || !attempt.expiresAt.Equal(cookie.Expires) {
		t.Fatal("could not recover the original login attempt with the matching cookie")
	}
	if query.Get("nonce") != attempt.nonce || query.Get("code_challenge") != attempt.pkceChallenge() || query.Get("code_challenge_method") != "S256" {
		t.Error("redirect nonce or PKCE parameters do not match the saved attempt")
	}
	if query.Has("code_verifier") || strings.Contains(target.String(), attempt.codeVerifier) || strings.Contains(target.String(), cookie.Value) {
		t.Error("redirect must not contain the verifier or browser token")
	}
}

func TestStartLoginRejectsInvalidEndpointWithoutSideEffects(t *testing.T) {
	store := newMemoryLoginAttempts()
	cfg := loginConfig{
		authorizationEndpoint: "http://idp.example/authorize",
		clientID:              "xprob-client",
		redirectURI:           "https://xprob.example/auth/callback",
	}
	router := gin.New()
	router.GET("/auth/login", startLoginHandler(store, cfg, time.Now))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if rec.Header().Get("Location") != "" || len(rec.Header().Values("Set-Cookie")) != 0 || len(store.byState) != 0 {
		t.Error("invalid configuration must not redirect, set a cookie or save a login attempt")
	}
}
