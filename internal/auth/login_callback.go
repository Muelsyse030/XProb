package auth

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

func consumeLoginCallback(r *http.Request, store *memoryLoginAttempts, now time.Time) (loginAttempt, string, bool) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || query.Has("error") {
		return loginAttempt{}, "", false
	}

	states := query["state"]
	if len(states) != 1 || states[0] == "" {
		return loginAttempt{}, "", false
	}

	codes := query["code"]
	if len(codes) != 1 || codes[0] == "" {
		return loginAttempt{}, "", false
	}

	cookies := r.CookiesNamed(loginCookieName)
	if len(cookies) != 1 || cookies[0].Value == "" {
		return loginAttempt{}, "", false
	}

	browserHash := sha256.Sum256([]byte(cookies[0].Value))
	attempt, ok := store.consume(states[0], browserHash, now)
	if !ok {
		return loginAttempt{}, "", false
	}

	return attempt, codes[0], true
}

func loginCallbackHandler(
	store *memoryLoginAttempts,
	authenticate func(context.Context, string, loginAttempt) (string, error),
	writer SessionWriter,
	now func() time.Time,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Referrer-Policy", "no-referrer")
		attempt, code, ok := consumeLoginCallback(c.Request, store, now())
		if !ok {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		clearCookie(c.Writer, loginCookieName, loginCallbackPath)

		ctx := c.Request.Context()
		userID, err := authenticate(ctx, code, attempt)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		issuedAt := now()
		expiresAt := issuedAt.Add(sessionTTL)
		token, err := IssueSession(ctx, writer, userID, issuedAt, expiresAt)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		SetSessionCookie(c.Writer, token, expiresAt)
		c.Redirect(http.StatusSeeOther, "/auth/me")
	}
}
