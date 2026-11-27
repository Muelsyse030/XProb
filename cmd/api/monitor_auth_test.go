package main

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"example.com/xprob/internal/auth"
	"example.com/xprob/internal/monitor"
	"example.com/xprob/internal/monitor/repo"
	"example.com/xprob/internal/monitor/service"
)

type sessionLookupFunc func(context.Context, [32]byte) (string, error)

func (f sessionLookupFunc) FindUserBySession(ctx context.Context, hash [32]byte) (string, error) {
	return f(ctx, hash)
}

type roleLookupFunc func(context.Context, string, string) (auth.Role, error)

func (f roleLookupFunc) FindRole(ctx context.Context, workspaceID, userID string) (auth.Role, error) {
	return f(ctx, workspaceID, userID)
}

func TestCreateMonitorWithBrowserAuth(t *testing.T) {
	const (
		token         = "opaque-route-test-token"
		userID        = "alice"
		monitorName   = "Homepage API"
		allowedOrigin = "http://127.0.0.1:9090"
	)
	tokenHash := sha256.Sum256([]byte(token))
	cases := []struct {
		name               string
		workspaceID        string
		cookie             string
		origins            []string
		wantStatus         int
		wantRoleLookups    int
		wantSessionLookups int
	}{
		{name: "wrong origin with valid session", workspaceID: "demo", cookie: token,
			origins: []string{"http://127.0.0.1:8080"}, wantStatus: http.StatusForbidden},
		{name: "missing origin with valid session", workspaceID: "demo", cookie: token,
			wantStatus: http.StatusForbidden},
		{name: "duplicate origins with valid session", workspaceID: "demo", cookie: token,
			origins: []string{allowedOrigin, allowedOrigin}, wantStatus: http.StatusForbidden},
		{name: "no cookie", workspaceID: "demo",
			origins: []string{allowedOrigin}, wantStatus: http.StatusUnauthorized},
		{name: "unknown session", workspaceID: "demo", cookie: "unknown",
			origins: []string{allowedOrigin}, wantStatus: http.StatusUnauthorized, wantSessionLookups: 1},
		{name: "viewer cannot create", workspaceID: "ops", cookie: token,
			origins: []string{allowedOrigin}, wantStatus: http.StatusForbidden, wantRoleLookups: 1, wantSessionLookups: 1},
		{name: "non-member cannot create", workspaceID: "other", cookie: token,
			origins: []string{allowedOrigin}, wantStatus: http.StatusNotFound, wantRoleLookups: 1, wantSessionLookups: 1},
		{name: "maintainer creates draft", workspaceID: "demo", cookie: token,
			origins: []string{allowedOrigin}, wantStatus: http.StatusCreated, wantRoleLookups: 1, wantSessionLookups: 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessionLookups := 0
			sessions := sessionLookupFunc(func(_ context.Context, hash [32]byte) (string, error) {
				sessionLookups++
				if hash != tokenHash {
					return "", auth.ErrInvalidSession
				}
				return userID, nil
			})
			roleLookups := 0
			roles := roleLookupFunc(func(_ context.Context, workspaceID, gotUserID string) (auth.Role, error) {
				roleLookups++
				if workspaceID != tc.workspaceID || gotUserID != userID {
					t.Errorf("FindRole(%q, %q), want (%q, %q)", workspaceID, gotUserID, tc.workspaceID, userID)
				}
				switch workspaceID {
				case "demo":
					return auth.RoleMaintainer, nil
				case "ops":
					return auth.RoleViewer, nil
				default:
					return "", auth.ErrNotMember
				}
			})

			store := repo.NewMemory()
			router := newRouter(store, routerAuth{sessions: sessions, roles: roles, origin: allowedOrigin})

			path := "/v1/workspaces/" + tc.workspaceID + "/monitors"
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"name":"`+monitorName+`"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-User-ID", "someone-else")
			for _, origin := range tc.origins {
				req.Header.Add("Origin", origin)
			}
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "xprob_session", Value: tc.cookie})
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body = %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if sessionLookups != tc.wantSessionLookups {
				t.Errorf("session lookups = %d, want %d", sessionLookups, tc.wantSessionLookups)
			}
			if roleLookups != tc.wantRoleLookups {
				t.Errorf("role lookups = %d, want %d", roleLookups, tc.wantRoleLookups)
			}
			saved, err := store.FindByWorkspaceID(context.Background(), tc.workspaceID)
			if err != nil {
				t.Fatalf("read saved drafts: %v", err)
			}
			if tc.wantStatus != http.StatusCreated {
				if len(saved) != 0 {
					t.Errorf("a denied request saved drafts: %+v", saved)
				}
				return
			}
			if len(saved) != 1 || saved[0].Name != monitorName || saved[0].Status != monitor.StatusDraft {
				t.Errorf("saved drafts = %+v, want one draft named %q", saved, monitorName)
			}
		})
	}
}

func TestMonitorReadsRequireWorkspaceMembership(t *testing.T) {
	store := repo.NewMemory()
	draft, err := service.New(store).CreateDraft(t.Context(), "demo", "Read test")
	if err != nil {
		t.Fatal(err)
	}
	sessions := sessionLookupFunc(func(_ context.Context, hash [32]byte) (string, error) {
		if hash == sha256.Sum256([]byte(testSessionToken)) {
			return "alice", nil
		}
		return "", auth.ErrInvalidSession
	})
	roles := roleLookupFunc(func(_ context.Context, workspaceID, userID string) (auth.Role, error) {
		if userID == "alice" {
			switch workspaceID {
			case "demo", "empty":
				return auth.RoleViewer, nil
			case "unknown-role":
				return auth.Role("unknown"), nil
			}
		}
		return "", auth.ErrNotMember
	})
	router := newRouter(store, routerAuth{sessions: sessions, roles: roles, origin: testOrigin})
	detail := "/v1/workspaces/demo/monitors/" + strconv.Itoa(draft.ID)
	cases := []struct {
		name, method, path string
		cookie             bool
		want               int
	}{
		{"viewer list", http.MethodGet, "/v1/workspaces/demo/monitors", true, http.StatusOK},
		{"viewer detail", http.MethodGet, detail, true, http.StatusOK},
		{"viewer head", http.MethodHead, detail, true, http.StatusOK},
		{"anonymous list", http.MethodGet, "/v1/workspaces/demo/monitors", false, http.StatusUnauthorized},
		{"anonymous head", http.MethodHead, detail, false, http.StatusUnauthorized},
		{"non-member list", http.MethodGet, "/v1/workspaces/other/monitors", true, http.StatusNotFound},
		{"other workspace's monitor", http.MethodGet, "/v1/workspaces/empty/monitors/" + strconv.Itoa(draft.ID), true, http.StatusNotFound},
		{"unknown role", http.MethodGet, "/v1/workspaces/unknown-role/monitors", true, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.cookie {
				req.AddCookie(&http.Cookie{Name: "xprob_session", Value: testSessionToken})
			}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Error("monitor response is missing Cache-Control: no-store")
			}
		})
	}
}

func TestRouterDoesNotBypassUnconfiguredAuth(t *testing.T) {
	router := newRouter(repo.NewMemory(), routerAuth{})
	const listPath = "/v1/workspaces/demo/monitors"
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, listPath},
		{http.MethodHead, listPath},
		{http.MethodPost, listPath},
		{http.MethodGet, listPath + "/1"},
		{http.MethodHead, listPath + "/1"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := newMonitorTestRequest(tc.method, tc.path, nil)
			req.Header.Del("Origin")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rec.Code)
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Error("monitor response is missing Cache-Control: no-store")
			}
		})
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("health status = %d, want 200", rec.Code)
	}
}
