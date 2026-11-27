package auth

import (
	"errors"
	"net/url"
)

func (a loginAttempt) authorizationURL(endpoint, clientID, redirectURI string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", errors.New("invalid HTTPS authorization endpoint")
	}

	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", errors.New("invalid authorization endpoint query")
	}
	q.Del("code_verifier")
	q.Set("response_type", "code")
	q.Set("response_mode", "query")
	q.Set("scope", "openid")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", a.state)
	q.Set("nonce", a.nonce)
	q.Set("code_challenge", a.pkceChallenge())
	q.Set("code_challenge_method", "S256")

	u.RawQuery = q.Encode()
	return u.String(), nil
}
