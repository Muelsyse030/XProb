package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

type monitorResponse struct {
	ID          int    `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
}

func TestCreateMonitorHTTP(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/workspaces/demo/monitors",
		strings.NewReader(`{"name":"  首页 API  "}`),
	)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router := newTestRouter()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("状态码 = %d，期望 %d；响应体：%s",
			rec.Code, http.StatusCreated, rec.Body.String())
	}

	var body monitorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应不是合法的 JSON：%v", err)
	}

	if body.ID == 0 || body.WorkspaceID != "demo" ||
		body.Name != "首页 API" || body.Status != "draft" {
		t.Errorf("草稿响应不符合预期：%+v", body)
	}

	id := strconv.Itoa(body.ID)
	getReq := httptest.NewRequest(http.MethodGet, "/v1/workspaces/demo/monitors/"+id, nil)
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("GET 状态码 = %d，期望 %d；响应体：%s",
			getRec.Code, http.StatusOK, getRec.Body.String())
	}

	var saved monitorResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &saved); err != nil {
		t.Fatalf("GET 响应不是合法的 JSON：%v", err)
	}
	if saved != body {
		t.Errorf("GET 读到 %+v，POST 创建的是 %+v", saved, body)
	}

	cases := []struct {
		name string
		path string
	}{
		{"other workspace", "/v1/workspaces/other/monitors/" + id},
		{"missing monitor", "/v1/workspaces/demo/monitors/" + strconv.Itoa(body.ID+1)},
		{"invalid ID", "/v1/workspaces/demo/monitors/not-a-number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s：状态码 = %d，期望 %d；响应体：%s",
					tc.path, rec.Code, http.StatusNotFound, rec.Body.String())
			}
		})
	}
}

func TestCreateMonitorErr(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodPost,
		"/v1/workspaces/demo/monitors",
		strings.NewReader(`{"name":" "}`),
	)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	newTestRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("状态码 = %d，期望 %d；响应体：%s",
			rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
}

func TestCreateMonitorRejectsBadBody(t *testing.T) {
	router := newTestRouter()
	cases := []struct {
		name   string
		body   string
		status int
	}{
		{"invalid JSON", `{"name":`, http.StatusBadRequest},
		{"trailing JSON", `{"name":"API"} {}`, http.StatusBadRequest},
		{"over 4 KiB", `{"name":"` + strings.Repeat("x", 4*1024) + `"}`, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/workspaces/demo/monitors", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("状态码 = %d，期望 %d；响应体：%s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

func TestListMonitorsHTTP(t *testing.T) {
	router := newTestRouter()
	createMonitor := func(workspaceID, body string) monitorResponse {
		t.Helper()
		path := "/v1/workspaces/" + workspaceID + "/monitors"
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusCreated {
			t.Fatalf("POST %s：状态码 = %d，期望 %d；响应体：%s",
				path, rec.Code, http.StatusCreated, rec.Body.String())
		}
		var created monitorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("POST %s：响应不是合法的 JSON：%v", path, err)
		}
		return created
	}

	first := createMonitor("demo", `{"name":"首页 API"}`)
	createMonitor("other", `{"name":"其他工作区 API"}`)
	second := createMonitor("demo", `{"name":"搜索 API"}`)

	t.Run("lists only the requested workspace in ID order", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/workspaces/demo/monitors", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("GET 状态码 = %d，期望 %d；响应体：%s",
				rec.Code, http.StatusOK, rec.Body.String())
		}
		var list []monitorResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatalf("GET 响应不是合法的 JSON 数组：%v", err)
		}
		if len(list) != 2 {
			t.Fatalf("列表有 %d 条，期望 2 条：%+v", len(list), list)
		}
		if list[0] != first || list[1] != second || list[0].ID >= list[1].ID {
			t.Errorf("列表 = %+v，期望按 ID 升序返回 %+v", list, []monitorResponse{first, second})
		}
	})

	t.Run("returns an empty JSON array", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/workspaces/empty/monitors", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("GET 状态码 = %d，期望 %d；响应体：%s",
				rec.Code, http.StatusOK, rec.Body.String())
		}
		if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
			t.Errorf("空列表响应 = %q，期望 %q", got, "[]")
		}
	})
}
