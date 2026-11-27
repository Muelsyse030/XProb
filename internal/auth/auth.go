package auth

type Role string

const (
	RoleAdmin      Role = "admin"
	RoleMaintainer Role = "maintainer"
	RoleViewer     Role = "viewer"
)

func canCreateMonitor(role Role) bool {
	switch role {
	case RoleAdmin, RoleMaintainer:
		return true
	default:
		return false
	}
}
