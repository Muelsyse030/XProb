package auth

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestNewLoginAttemptGeneratesDistinctValues(t *testing.T) {
	now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
	attempt := newLoginAttempt(now)
	values := []struct {
		name  string
		value string
	}{
		{"state", attempt.state},
		{"nonce", attempt.nonce},
		{"codeVerifier", attempt.codeVerifier},
	}
	seen := make(map[string]string, len(values))
	for _, field := range values {
		decoded, err := base64.RawURLEncoding.DecodeString(field.value)
		if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != field.value {
			t.Errorf("%s is not unpadded URL-safe Base64", field.name)
		} else if len(decoded) != 32 {
			t.Errorf("%s decodes to %d bytes, want 32", field.name, len(decoded))
		}
		if previous, ok := seen[field.value]; ok {
			t.Errorf("%s and %s reused the same value", previous, field.name)
		}
		seen[field.value] = field.name
	}

	next := newLoginAttempt(now)
	for _, field := range []struct {
		name  string
		value string
	}{
		{"state", next.state},
		{"nonce", next.nonce},
		{"codeVerifier", next.codeVerifier},
	} {
		if _, ok := seen[field.value]; ok {
			t.Errorf("next attempt reused a previous value for %s", field.name)
		}
	}
}

func TestNewLoginAttemptExpiresFiveMinutesAfterProvidedTime(t *testing.T) {
	now := time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC)
	attempt := newLoginAttempt(now)
	want := now.Add(5 * time.Minute)
	if !attempt.expiresAt.Equal(want) {
		t.Errorf("expiresAt = %s, want %s", attempt.expiresAt, want)
	}
}

func TestPKCEChallengeS256(t *testing.T) {
	attempt := loginAttempt{codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := attempt.pkceChallenge(); got != want {
		t.Errorf("pkceChallenge() = %q, want %q", got, want)
	}
}
