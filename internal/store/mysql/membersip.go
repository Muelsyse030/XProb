package mysql

import (
	"context"
	"errors"

	"example.com/xprob/internal/auth"
	"gorm.io/gorm"
)

func (r *Repository) FindRole(ctx context.Context, workspaceID, userID string) (auth.Role, error) {
	var row struct {
		Role auth.Role
	}

	err := r.db.WithContext(ctx).
		Table("memberships").
		Select("role").
		Where("workspace_id = ? AND user_id = ?", workspaceID, userID).
		Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", auth.ErrNotMember
	}
	if err != nil {
		return "", err
	}
	return row.Role, nil
}
