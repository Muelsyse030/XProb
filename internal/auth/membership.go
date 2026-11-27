package auth

import (
	"context"
	"errors"
)

var ErrNotMember = errors.New("workspace membership not found")

type RoleReader interface {
	FindRole(ctx context.Context, workspaceID, userID string) (Role, error)
}
