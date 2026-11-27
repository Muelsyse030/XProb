package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type roleReaderFunc func(context.Context, string, string) (Role, error)

func (f roleReaderFunc) FindRole(ctx context.Context, workspaceID, userID string) (Role, error) {
	return f(ctx, workspaceID, userID)
}

func TestRequireMonitorWrite(t *testing.T) {
	cases := []struct {
		name        string
		userID      string
		identified  bool
		role        Role
		lookupErr   error
		wantStatus  int
		wantLookup  bool
		wantHandler bool
	}{
		{name: "unauthenticated", wantStatus: http.StatusUnauthorized},
		{name: "empty user ID", identified: true, wantStatus: http.StatusUnauthorized},
		{name: "not a workspace member", userID: "alice", identified: true,
			lookupErr: fmt.Errorf("lookup membership: %w", ErrNotMember), wantStatus: http.StatusNotFound, wantLookup: true},
		{name: "role lookup failed", userID: "alice", identified: true,
			lookupErr: errors.New("database unavailable"), wantStatus: http.StatusInternalServerError, wantLookup: true},
		{name: "viewer denied", userID: "alice", identified: true,
			role: RoleViewer, wantStatus: http.StatusForbidden, wantLookup: true},
		{name: "unknown role denied", userID: "alice", identified: true,
			role: Role("admn"), wantStatus: http.StatusForbidden, wantLookup: true},
		{name: "maintainer allowed", userID: "alice", identified: true,
			role: RoleMaintainer, wantStatus: http.StatusCreated, wantLookup: true, wantHandler: true},
		{name: "admin allowed", userID: "alice", identified: true,
			role: RoleAdmin, wantStatus: http.StatusCreated, wantLookup: true, wantHandler: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookupCalled := false
			roles := roleReaderFunc(func(_ context.Context, workspaceID, userID string) (Role, error) {
				lookupCalled = true
				if workspaceID != "demo" || userID != tc.userID {
					t.Errorf("FindRole called with (%q, %q), want (%q, %q)", workspaceID, userID, "demo", tc.userID)
				}
				return tc.role, tc.lookupErr
			})
			resolveUserID := func(*gin.Context) (string, bool) {
				return tc.userID, tc.identified
			}

			handlerRan := false
			router := gin.New()
			router.POST("/v1/workspaces/:workspaceId/monitors",
				RequireMonitorWrite(roles, resolveUserID),
				func(c *gin.Context) {
					handlerRan = true
					c.Status(http.StatusCreated)
				},
			)

			req := httptest.NewRequest(http.MethodPost, "/v1/workspaces/demo/monitors", nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if lookupCalled != tc.wantLookup {
				t.Errorf("lookupCalled = %t, want %t", lookupCalled, tc.wantLookup)
			}
			if handlerRan != tc.wantHandler {
				t.Errorf("handlerRan = %t, want %t", handlerRan, tc.wantHandler)
			}
		})
	}
}
