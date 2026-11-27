package auth

import (
	"crypto/sha256"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func logoutHandler(sessions SessionRevoker) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookies := c.Request.CookiesNamed(sessionCookieName)
		if len(cookies) > 1 {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		if len(cookies) == 1 && cookies[0].Value != "" {
			hash := sha256.Sum256([]byte(cookies[0].Value))
			if err := sessions.RevokeSession(c.Request.Context(), hash); err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
		}
		clearCookie(c.Writer, sessionCookieName, "/")
		c.Status(http.StatusNoContent)
	}
}

func clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Path: path, MaxAge: -1, Expires: time.Unix(1, 0).UTC(),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}
