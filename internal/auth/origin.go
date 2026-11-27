package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RequireSameOrigin(allowedOrigin string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origins := c.Request.Header.Values("Origin")

		if len(origins) != 1 {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		origin := origins[0]
		if origin == "" || origin == "null" || origin != allowedOrigin {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}
