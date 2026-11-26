package handler

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"

	"example.com/xprob/internal/monitor"
	"example.com/xprob/internal/monitor/service"
	"github.com/gin-gonic/gin"
)

const maxCreateBodyBytes = 4 * 1024

type Handler struct {
	service *service.Service
}

func New(s *service.Service) *Handler {
	return &Handler{service: s}
}

type createMonitorRequest struct {
	Name string `json:"name"`
}

type monitorResponse struct {
	ID          int    `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
}

func (h *Handler) Create(c *gin.Context) {
	data, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxCreateBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(c.Writer, "request body is too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(c.Writer, "could not read request body", http.StatusBadRequest)
		return
	}

	var req createMonitorRequest
	if err := json.Unmarshal(data, &req); err != nil {
		http.Error(c.Writer, "invalid JSON request", http.StatusBadRequest)
		return
	}

	draft, err := h.service.CreateDraft(c.Request.Context(), c.Param("workspaceId"), req.Name)
	if errors.Is(err, service.ErrNameRequired) {
		http.Error(c.Writer, service.ErrNameRequired.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		writeInternalError(c, "create monitor draft", err)
		return
	}
	writeMonitor(c, http.StatusCreated, draft)
}

func (h *Handler) Get(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		http.NotFound(c.Writer, c.Request)
		return
	}

	m, err := h.service.GetMonitor(c.Request.Context(), c.Param("workspaceId"), id)
	if errors.Is(err, monitor.ErrNotFound) {
		http.NotFound(c.Writer, c.Request)
		return
	}
	if err != nil {
		writeInternalError(c, "get monitor", err)
		return
	}
	writeMonitor(c, http.StatusOK, m)
}

func (h *Handler) GetMonitorByWorkspaceID(c *gin.Context) {
	list, err := h.service.GetMonitorByWorkspaceID(c.Request.Context(), c.Param("workspaceId"))
	if err != nil {
		writeInternalError(c, "list monitors", err)
		return
	}
	items := make([]monitorResponse, 0, len(list))
	for _, m := range list {
		items = append(items, toMonitorResponse(m))
	}
	c.JSON(http.StatusOK, items)
}

func toMonitorResponse(m monitor.Monitor) monitorResponse {
	return monitorResponse{
		ID:          m.ID,
		WorkspaceID: m.WorkspaceID,
		Name:        m.Name,
		Status:      m.Status,
	}
}

func writeMonitor(c *gin.Context, statusCode int, m monitor.Monitor) {
	c.JSON(statusCode, toMonitorResponse(m))
}

func writeInternalError(c *gin.Context, operation string, err error) {
	log.Printf("%s: %v", operation, err)
	http.Error(c.Writer, "internal server error", http.StatusInternalServerError)
}
