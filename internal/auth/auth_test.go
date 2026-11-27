package auth

import "testing"

func TestCanCreateMonitor(t *testing.T) {
	cases := []struct {
		name string
		role Role
		want bool
	}{
		{name: "管理员可以创建", role: RoleAdmin, want: true},
		{name: "维护者可以创建", role: RoleMaintainer, want: true},
		{name: "只读成员不能创建", role: RoleViewer, want: false},
		{name: "未知角色不能创建", role: Role("admn"), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := canCreateMonitor(tc.role); got != tc.want {
				t.Errorf("canCreateMonitor(%q) = %t，期望 %t", tc.role, got, tc.want)
			}
		})
	}
}
