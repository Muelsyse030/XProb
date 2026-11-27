package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	sessionCookieName = "xprob_session"
	sessionUserIDKey  = "xprob.auth.session_user_id"
)

var ErrInvalidSession = errors.New("invalid session")

type SessionReader interface {
	FindUserBySession(ctx context.Context, tokenHash [32]byte) (string, error)
}

func RequireSession(sessions SessionReader) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookies := c.Request.CookiesNamed(sessionCookieName)
		if len(cookies) != 1 || cookies[0].Value == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tokenHash := sha256.Sum256([]byte(cookies[0].Value))
		userID, err := sessions.FindUserBySession(c.Request.Context(), tokenHash)

		switch {
		case errors.Is(err, ErrInvalidSession):
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		case err != nil, userID == "":
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		c.Set(sessionUserIDKey, userID)
		c.Next()
	}
}

func SessionUserID(c *gin.Context) (string, bool) {
	userID := c.GetString(sessionUserIDKey)
	return userID, userID != ""
}
