package auth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

func RequireMonitorWrite(roles RoleReader, resolveUserID func(*gin.Context) (string, bool)) gin.HandlerFunc {
	return requireWorkspaceRole(roles, resolveUserID, canCreateMonitor)
}

func RequireMonitorRead(roles RoleReader, resolveUserID func(*gin.Context) (string, bool)) gin.HandlerFunc {
	return requireWorkspaceRole(roles, resolveUserID, func(role Role) bool {
		return role == RoleViewer || canCreateMonitor(role)
	})
}

func requireWorkspaceRole(
	roles RoleReader,
	resolveUserID func(*gin.Context) (string, bool),
	allowed func(Role) bool,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := resolveUserID(c)
		if !ok || userID == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		role, err := roles.FindRole(c.Request.Context(), c.Param("workspaceId"), userID)
		switch {
		case errors.Is(err, ErrNotMember):
			c.AbortWithStatus(http.StatusNotFound)
			return
		case err != nil:
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		case !allowed(role):
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}
