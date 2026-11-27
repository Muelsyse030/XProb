package auth

import (
	"context"
	"errors"
	"strings"
	"time"
)

type SessionWriter interface {
	CreateSession(ctx context.Context, tokenHash [32]byte, userID string, expiresAt time.Time) error
}

func IssueSession(ctx context.Context, writer SessionWriter, userID string, issuedAt, expiresAt time.Time) (string, error) {
	if strings.TrimSpace(userID) == "" {
		return "", errors.New("user ID is required")
	}
	if !expiresAt.After(issuedAt) {
		return "", errors.New("expiration must be in the future")
	}
	token, tokenHash := newSessionToken()
	err := writer.CreateSession(ctx, tokenHash, userID, expiresAt)
	if err != nil {
		return "", err
	}
	return token, nil
}
