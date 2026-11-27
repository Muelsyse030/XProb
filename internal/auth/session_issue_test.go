package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

type sessionWriterFunc func(context.Context, [32]byte, string, time.Time) error

func (f sessionWriterFunc) CreateSession(ctx context.Context, hash [32]byte, userID string, expiresAt time.Time) error {
	return f(ctx, hash, userID, expiresAt)
}

func TestIssueSessionRejectsInvalidInput(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	cases := []struct {
		name      string
		userID    string
		expiresAt time.Time
	}{
		{name: "empty user ID", expiresAt: now.Add(time.Hour)},
		{name: "blank user ID", userID: " \t ", expiresAt: now.Add(time.Hour)},
		{name: "past expiration", userID: "alice", expiresAt: now.Add(-time.Hour)},
		{name: "expiration at issuance", userID: "alice", expiresAt: now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writer := sessionWriterFunc(func(context.Context, [32]byte, string, time.Time) error {
				t.Fatal("CreateSession must not be called for invalid input")
				return nil
			})
			token, err := IssueSession(t.Context(), writer, tc.userID, now, tc.expiresAt)
			if err == nil || token != "" {
				t.Errorf("got error %v and nonempty token = %t; want an error and no token", err, token != "")
			}
		})
	}
}

func TestIssueSessionSavesHashBeforeReturningToken(t *testing.T) {
	const userID = "alice"
	now := time.Unix(0, 0).UTC()
	expiresAt := now.Add(time.Hour)
	var savedHash [32]byte
	writes := 0
	writer := sessionWriterFunc(func(_ context.Context, hash [32]byte, gotUserID string, gotExpiry time.Time) error {
		writes++
		savedHash = hash
		if gotUserID != userID || !gotExpiry.Equal(expiresAt) {
			t.Errorf("CreateSession got user %q and expiration %v; want %q and %v", gotUserID, gotExpiry, userID, expiresAt)
		}
		return nil
	})
	token, err := IssueSession(t.Context(), writer, userID, now, expiresAt)
	if err != nil || token == "" {
		t.Fatalf("got error %v and nonempty token = %t; want success with a token", err, token != "")
	}
	if writes != 1 || savedHash != sha256.Sum256([]byte(token)) {
		t.Errorf("got %d writes; want one write with the token digest", writes)
	}
}

func TestIssueSessionDoesNotReturnTokenWhenWriteFails(t *testing.T) {
	wantErr := errors.New("session storage unavailable")
	writer := sessionWriterFunc(func(context.Context, [32]byte, string, time.Time) error {
		return wantErr
	})
	now := time.Unix(0, 0).UTC()
	token, err := IssueSession(t.Context(), writer, "alice", now, now.Add(time.Hour))
	if !errors.Is(err, wantErr) || token != "" {
		t.Errorf("got error %v and nonempty token = %t; want %v and no token", err, token != "", wantErr)
	}
}
