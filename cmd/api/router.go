package main

import (
	"log"
	"net/http"
	"runtime/debug"

	"example.com/xprob/internal/auth"
	"example.com/xprob/internal/monitor/handler"
	"example.com/xprob/internal/monitor/service"
	"github.com/gin-gonic/gin"
)

type routerAuth struct {
	sessions auth.SessionReader
	roles    auth.RoleReader
	origin   string
	login    *auth.Login
}

func newRouter(repository service.Repository, access routerAuth) *gin.Engine {
	monitorHandler := handler.New(service.New(repository))
	router := gin.New()
	router.Use(gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, _ any) {
		log.Printf("HTTP panic recovered on registered route %q\n%s", c.FullPath(), debug.Stack())
		c.AbortWithStatus(http.StatusInternalServerError)
	}))
	router.HandleMethodNotAllowed = true
	router.RedirectTrailingSlash = false

	readMethods := []string{http.MethodGet, http.MethodHead}
	router.Match(readMethods, "/healthz", health)
	if access.login != nil {
		access.login.RegisterRoutes(router)
	}
	monitors := router.Group("/v1/workspaces/:workspaceId/monitors", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Next()
	})

	reads, writes := monitors, monitors
	if access.sessions == nil || access.roles == nil || access.origin == "" {
		monitors.Use(func(c *gin.Context) { c.AbortWithStatus(http.StatusUnauthorized) })
	} else {
		session := auth.RequireSession(access.sessions)
		reads = monitors.Group("", session, auth.RequireMonitorRead(access.roles, auth.SessionUserID))
		writes = monitors.Group("", auth.RequireSameOrigin(access.origin), session,
			auth.RequireMonitorWrite(access.roles, auth.SessionUserID))
	}
	writes.POST("", monitorHandler.Create)
	reads.Match(readMethods, "", monitorHandler.List)
	reads.Match(readMethods, "/:id", monitorHandler.Get)
	return router
}

func health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
