package mysql

import (
	"context"
	"errors"
	"time"

	"example.com/xprob/internal/auth"
	"gorm.io/gorm"
)

func (r *Repository) FindUserBySession(ctx context.Context, tokenHash [32]byte) (string, error) {
	var row struct {
		UserID string `gorm:"column:user_id"`
	}
	err := r.db.WithContext(ctx).
		Table("sessions").
		Select("user_id").
		Where("token_hash = ? AND expires_at > UTC_TIMESTAMP(6) AND revoked_at IS NULL", tokenHash[:]).
		Take(&row).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", auth.ErrInvalidSession
	}
	if err != nil {
		return "", err
	}
	return row.UserID, nil
}

func (r *Repository) CreateSession(ctx context.Context, tokenHash [32]byte, userID string, expiresAt time.Time) error {
	return r.db.WithContext(ctx).Table("sessions").Create(map[string]any{
		"token_hash": tokenHash[:],
		"user_id":    userID,
		"expires_at": expiresAt.UTC(),
	}).Error
}

var _ auth.SessionStore = (*Repository)(nil)

func (r *Repository) RevokeSession(ctx context.Context, tokenHash [32]byte) error {
	return r.db.WithContext(ctx).Table("sessions").
		Where("token_hash = ? AND revoked_at IS NULL", tokenHash[:]).
		Update("revoked_at", gorm.Expr("UTC_TIMESTAMP(6)")).Error
}
