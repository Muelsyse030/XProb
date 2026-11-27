package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func newSessionToken() (token string, tokenHash [32]byte) {
	var tokenhash [32]byte
	_, err := rand.Read(tokenhash[:])
	if err != nil {
		return
	}
	token = base64.RawURLEncoding.EncodeToString(tokenhash[:])
	return token, sha256.Sum256([]byte(token))
}
