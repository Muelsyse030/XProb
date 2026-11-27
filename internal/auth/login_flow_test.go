package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	flowOrigin = "https://xprob.example"
	flowClient = "xprob-client"
)

type flowSessionStore struct {
	sessions map[[32]byte]string
	writeErr error
}

func (s *flowSessionStore) CreateSession(_ context.Context, hash [32]byte, userID string, _ time.Time) error {
	if s.writeErr != nil {
		return s.writeErr
	}
	s.sessions[hash] = userID
	return nil
}

func (s *flowSessionStore) FindUserBySession(_ context.Context, hash [32]byte) (string, error) {
	if id, ok := s.sessions[hash]; ok {
		return id, nil
	}
	return "", ErrInvalidSession
}

func (s *flowSessionStore) RevokeSession(_ context.Context, hash [32]byte) error {
	delete(s.sessions, hash)
	return nil
}

func signedTestIDToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	encode := base64.RawURLEncoding.EncodeToString
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	message := encode([]byte(`{"alg":"RS256","kid":"test-key"}`)) + "." + encode(payload)
	digest := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return message + "." + encode(signature)
}

func TestOIDCLoginFlow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		change    func(map[string]any)
		wrongKey  bool
		noIDToken bool
		writeFail bool
		status    int
	}{
		{name: "success", status: http.StatusSeeOther},
		{name: "wrong nonce", change: func(c map[string]any) { c["nonce"] = "other" }, status: http.StatusUnauthorized},
		{name: "wrong issuer", change: func(c map[string]any) { c["iss"] = "https://other.example" }, status: http.StatusUnauthorized},
		{name: "wrong audience", change: func(c map[string]any) { c["aud"] = "other-client" }, status: http.StatusUnauthorized},
		{name: "wrong authorized party", change: func(c map[string]any) { c["azp"] = "other-client" }, status: http.StatusUnauthorized},
		{name: "expired ID token", change: func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }, status: http.StatusUnauthorized},
		{name: "wrong signature", wrongKey: true, status: http.StatusUnauthorized},
		{name: "missing ID token", noIDToken: true, status: http.StatusUnauthorized},
		{name: "session write failed", writeFail: true, status: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokenRequest := make(chan url.Values, 2)
			signedToken := make(chan string, 1)
			mux := http.NewServeMux()
			provider := httptest.NewTLSServer(mux)
			defer provider.Close()
			mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
				writeTestJSON(w, map[string]any{
					"issuer": provider.URL, "authorization_endpoint": provider.URL + "/authorize",
					"token_endpoint": provider.URL + "/token", "jwks_uri": provider.URL + "/keys",
					"id_token_signing_alg_values_supported": []string{"RS256"},
				})
			})
			mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
				writeTestJSON(w, map[string]any{"keys": []map[string]string{{
					"kty": "RSA", "kid": "test-key", "alg": "RS256",
					"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
					"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
				}}})
			})
			mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
				id, secret, _ := r.BasicAuth()
				if r.ParseForm() != nil || id != flowClient || secret != "test-client-secret" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				select {
				case tokenRequest <- r.PostForm:
				default:
				}
				response := map[string]any{"access_token": "test-access-token", "token_type": "Bearer"}
				if !tc.noIDToken {
					select {
					case response["id_token"] = <-signedToken:
					default:
						w.WriteHeader(http.StatusBadRequest)
						return
					}
				}
				writeTestJSON(w, response)
			})

			store := &flowSessionStore{sessions: make(map[[32]byte]string)}
			if tc.writeFail {
				store.writeErr = errors.New("session store down")
			}
			login, err := newLogin(t.Context(), OIDCConfig{
				Issuer: provider.URL, ClientID: flowClient, ClientSecret: "test-client-secret", Origin: flowOrigin,
			}, store, provider.Client())
			if err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			login.RegisterRoutes(router)
			start := doLoginRequest(router, http.MethodGet, "/auth/login", "", nil)
			if start.Code != http.StatusFound {
				t.Fatalf("start status = %d, want 302", start.Code)
			}
			target, err := url.Parse(start.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			query := target.Query()
			browserCookie := responseCookie(t, start, loginCookieName)
			claims := map[string]any{
				"iss": provider.URL, "sub": "alice", "aud": flowClient, "nonce": query.Get("nonce"),
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
			}
			if tc.change != nil {
				tc.change(claims)
			}
			signer := key
			if tc.wrongKey {
				signer = otherKey
			}
			signedToken <- signedTestIDToken(t, signer, claims)
			callback := loginCallbackPath + "?" + url.Values{"state": {query.Get("state")}, "code": {"test-code"}}.Encode()
			result := doLoginRequest(router, http.MethodGet, callback, "", browserCookie)
			if result.Code != tc.status {
				t.Fatalf("callback status = %d, want %d", result.Code, tc.status)
			}
			select {
			case form := <-tokenRequest:
				digest := sha256.Sum256([]byte(form.Get("code_verifier")))
				if form.Get("code") != "test-code" || form.Get("grant_type") != "authorization_code" ||
					form.Get("redirect_uri") != flowOrigin+loginCallbackPath ||
					base64.RawURLEncoding.EncodeToString(digest[:]) != query.Get("code_challenge") {
					t.Error("exchange did not send the expected code, redirect URI and PKCE verifier")
				}
			default:
				t.Fatal("no token exchange request")
			}
			if responseCookie(t, result, loginCookieName).MaxAge >= 0 {
				t.Error("callback did not clear the temporary cookie")
			}
			if replay := doLoginRequest(router, http.MethodGet, callback, "", browserCookie); replay.Code != http.StatusBadRequest {
				t.Errorf("replay status = %d, want 400", replay.Code)
			}
			if tc.status != http.StatusSeeOther {
				for _, cookie := range result.Result().Cookies() {
					if cookie.Name == sessionCookieName {
						t.Error("failed login emitted a session cookie")
					}
				}
				if len(store.sessions) != 0 {
					t.Error("failed login saved a session")
				}
				return
			}

			if result.Header().Get("Location") != "/auth/me" {
				t.Error("successful login must redirect to /auth/me")
			}
			session := responseCookie(t, result, sessionCookieName)
			me := doLoginRequest(router, http.MethodGet, "/auth/me", "", session)
			var body struct {
				UserID string `json:"user_id"`
			}
			digest := sha256.Sum256([]byte(provider.URL + "\x00alice"))
			wantUserID := "oidc:" + hex.EncodeToString(digest[:])
			if me.Code != http.StatusOK || json.Unmarshal(me.Body.Bytes(), &body) != nil || body.UserID != wantUserID {
				t.Error("/auth/me did not return the verified issuer/subject ID")
			}
			if wrongOrigin := doLoginRequest(router, http.MethodPost, "/auth/logout", "https://other.example", session); wrongOrigin.Code != http.StatusForbidden {
				t.Errorf("cross-origin logout status = %d, want 403", wrongOrigin.Code)
			}
			if stillActive := doLoginRequest(router, http.MethodGet, "/auth/me", "", session); stillActive.Code != http.StatusOK {
				t.Error("cross-origin logout changed the session")
			}
			logout := doLoginRequest(router, http.MethodPost, "/auth/logout", flowOrigin, session)
			if logout.Code != http.StatusNoContent || responseCookie(t, logout, sessionCookieName).MaxAge >= 0 {
				t.Error("logout did not revoke the session and clear its cookie")
			}
			if after := doLoginRequest(router, http.MethodGet, "/auth/me", "", session); after.Code != http.StatusUnauthorized {
				t.Errorf("revoked cookie status = %d, want 401", after.Code)
			}
		})
	}
}

func doLoginRequest(router http.Handler, method, path, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func responseCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	resp := rec.Result()
	defer resp.Body.Close()
	for _, cookie := range resp.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("missing %s cookie", name)
	return nil
}

func writeTestJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
