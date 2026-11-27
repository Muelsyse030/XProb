package mysql

import (
	"crypto/rand"
	"errors"
	"testing"

	"example.com/xprob/internal/auth"
)

func TestFindRole(t *testing.T) {
	ctx, repo := newTestRepository(t)
	tx := repo.db
	var reader auth.RoleReader = repo

	prefix := "test-find-role-" + rand.Text()
	demoID, opsID := prefix+"-demo", prefix+"-ops"
	workspaces := []map[string]any{
		{"id": demoID, "name": "Demo"},
		{"id": opsID, "name": "Ops"},
	}
	if err := tx.Table("workspaces").Create(workspaces).Error; err != nil {
		t.Fatalf("准备工作区：%v", err)
	}
	memberships := []map[string]any{
		{"workspace_id": demoID, "user_id": "alice", "role": auth.RoleAdmin},
		{"workspace_id": opsID, "user_id": "alice", "role": auth.RoleViewer},
		{"workspace_id": demoID, "user_id": "bob", "role": auth.RoleMaintainer},
	}
	if err := tx.Table("memberships").Create(memberships).Error; err != nil {
		t.Fatalf("准备成员记录：%v", err)
	}

	cases := []struct {
		name        string
		workspaceID string
		userID      string
		wantRole    auth.Role
		wantErr     error
	}{
		{name: "alice is admin in demo", workspaceID: demoID, userID: "alice", wantRole: auth.RoleAdmin},
		{name: "alice is viewer in ops", workspaceID: opsID, userID: "alice", wantRole: auth.RoleViewer},
		{name: "bob is maintainer in demo", workspaceID: demoID, userID: "bob", wantRole: auth.RoleMaintainer},
		{name: "bob is not a member of ops", workspaceID: opsID, userID: "bob", wantErr: auth.ErrNotMember},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			role, err := reader.FindRole(ctx, tc.workspaceID, tc.userID)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("FindRole 错误 = %v，期望 %v", err, tc.wantErr)
			}
			if role != tc.wantRole {
				t.Errorf("FindRole 角色 = %q，期望 %q", role, tc.wantRole)
			}
		})
	}
}
