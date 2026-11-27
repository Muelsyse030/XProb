package auth

import (
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestAuthorizationURL(t *testing.T) {
	attempt := loginAttempt{
		state:        "login-state",
		nonce:        "login-nonce",
		codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	}
	const endpoint = "https://idp.example/authorize?prompt=login&state=old&state=duplicate"
	const callback = "https://xprob.example/auth/callback?source=web&lang=zh"

	got, err := attempt.authorizationURL(endpoint, "xprob-client", callback)
	if err != nil {
		t.Fatalf("build authorization URL: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	if u.Scheme != "https" || u.Host != "idp.example" || u.Path != "/authorize" {
		t.Errorf("unexpected authorization endpoint: scheme=%q host=%q path=%q", u.Scheme, u.Host, u.Path)
	}
	query := u.Query()
	want := map[string]string{
		"response_type":         "code",
		"scope":                 "openid",
		"client_id":             "xprob-client",
		"redirect_uri":          callback,
		"state":                 attempt.state,
		"nonce":                 attempt.nonce,
		"code_challenge":        attempt.pkceChallenge(),
		"code_challenge_method": "S256",
		"prompt":                "login",
	}
	for key, value := range want {
		if got := query[key]; !slices.Equal(got, []string{value}) {
			t.Errorf("query[%q] = %q, want exactly one value %q", key, got, value)
		}
	}
	if query.Has("code_verifier") || strings.Contains(got, attempt.codeVerifier) {
		t.Error("authorization URL must not contain the original PKCE verifier")
	}
}

func TestAuthorizationURLRejectsInvalidEndpoints(t *testing.T) {
	attempt := loginAttempt{}
	cases := []struct {
		name     string
		endpoint string
	}{
		{"HTTP endpoint", "http://idp.example/authorize"},
		{"relative URL", "/authorize"},
		{"missing host", "https:///authorize"},
		{"embedded credentials", "https://user:password@idp.example/authorize"},
		{"fragment", "https://idp.example/authorize#fragment"},
		{"malformed URL", "https://[invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := attempt.authorizationURL(tc.endpoint, "xprob-client", "https://xprob.example/auth/callback")
			if err == nil || got != "" {
				t.Errorf("got nonempty URL = %t and error %v; want no URL and an error", got != "", err)
			}
		})
	}
}
