package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequireSameOriginRejectsOpaqueOrigin(t *testing.T) {
	router := gin.New()
	router.POST("/monitors", RequireSameOrigin("null"), func(c *gin.Context) {
		t.Error("an opaque origin reached the write handler")
		c.Status(http.StatusCreated)
	})
	req := httptest.NewRequest(http.MethodPost, "/monitors", nil)
	req.Header.Set("Origin", "null")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
