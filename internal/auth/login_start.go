package auth

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type loginConfig struct {
	authorizationEndpoint string
	clientID              string
	redirectURI           string
}

const (
	loginCookieName   = "xprob_login"
	loginCallbackPath = "/auth/callback"
)

func startLoginHandler(store *memoryLoginAttempts, cfg loginConfig, now func() time.Time) gin.HandlerFunc {
	return func(c *gin.Context) {
		startedAt := now()
		attempt := newLoginAttempt(startedAt)
		targetURL, err := attempt.authorizationURL(
			cfg.authorizationEndpoint,
			cfg.clientID,
			cfg.redirectURI,
		)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		browserToken, browserTokenHash := newSessionToken()
		if !store.save(attempt, browserTokenHash, startedAt) {
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}

		c.Header("Cache-Control", "no-store")
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     loginCookieName,
			Value:    browserToken,
			Path:     loginCallbackPath,
			Expires:  attempt.expiresAt.UTC(),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})

		c.Redirect(http.StatusFound, targetURL)
	}
}
