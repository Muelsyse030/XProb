package main

import (
	"net/http"

	"example.com/xprob/internal/monitor/handler"
	"example.com/xprob/internal/monitor/service"
	"github.com/gin-gonic/gin"
)

func newRouter(repository service.Repository) *gin.Engine {
	monitorService := service.New(repository)
	monitorHandler := handler.New(monitorService)

	router := gin.New()
	router.Use(gin.Recovery())
	router.HandleMethodNotAllowed = true
	router.RedirectTrailingSlash = false

	readMethods := []string{http.MethodGet, http.MethodHead}
	router.Match(readMethods, "/healthz", health)
	monitors := router.Group("/v1/workspaces/:workspaceId/monitors")
	monitors.POST("", monitorHandler.Create)
	monitors.Match(readMethods, "/:id", monitorHandler.Get)
	monitors.GET("", monitorHandler.GetMonitorByWorkspaceID)
	return router
}

func health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
