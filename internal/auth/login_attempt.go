package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"
)

type loginAttempt struct {
	state        string
	nonce        string
	codeVerifier string
	expiresAt    time.Time
}

func newLoginAttempt(now time.Time) loginAttempt {
	generate := func() string {
		var buf [32]byte
		rand.Read(buf[:])
		return base64.RawURLEncoding.EncodeToString(buf[:])
	}
	return loginAttempt{
		state:        generate(),
		nonce:        generate(),
		codeVerifier: generate(),
		expiresAt:    now.Add(5 * time.Minute),
	}
}

func (a loginAttempt) pkceChallenge() string {
	digest := sha256.Sum256([]byte(a.codeVerifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
