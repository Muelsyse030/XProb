package mysql

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"example.com/xprob/internal/auth"
	driver "github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
)

func TestFindUserBySession(t *testing.T) {
	ctx, repo := newTestRepository(t)
	tx := repo.db
	var reader auth.SessionReader = repo

	userID := "test-find-session-" + rand.Text()
	valid := sha256.Sum256([]byte(userID + ":valid"))
	expired := sha256.Sum256([]byte(userID + ":expired"))
	revoked := sha256.Sum256([]byte(userID + ":revoked"))
	missing := sha256.Sum256([]byte(userID + ":missing"))
	future := gorm.Expr("UTC_TIMESTAMP(6) + INTERVAL 1 HOUR")
	past := gorm.Expr("UTC_TIMESTAMP(6) - INTERVAL 1 HOUR")
	rows := []map[string]any{
		{"token_hash": valid[:], "user_id": userID, "expires_at": future, "revoked_at": nil},
		{"token_hash": expired[:], "user_id": userID, "expires_at": past, "revoked_at": nil},
		{"token_hash": revoked[:], "user_id": userID, "expires_at": future, "revoked_at": past},
	}
	if err := tx.Table("sessions").Create(rows).Error; err != nil {
		t.Fatalf("insert session fixtures: %v", err)
	}

	cases := []struct {
		name     string
		hash     [32]byte
		wantUser string
		wantErr  error
	}{
		{name: "valid", hash: valid, wantUser: userID},
		{name: "expired", hash: expired, wantErr: auth.ErrInvalidSession},
		{name: "revoked before expiry", hash: revoked, wantErr: auth.ErrInvalidSession},
		{name: "unknown hash", hash: missing, wantErr: auth.ErrInvalidSession},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := reader.FindUserBySession(ctx, tc.hash)
			if !errors.Is(err, tc.wantErr) || got != tc.wantUser {
				t.Errorf("FindUserBySession = (%q, %v), want (%q, %v)", got, err, tc.wantUser, tc.wantErr)
			}
		})
	}

	t.Run("preserves query cancellation", func(t *testing.T) {
		canceled, stop := context.WithCancel(ctx)
		stop()
		got, err := reader.FindUserBySession(canceled, valid)
		if !errors.Is(err, context.Canceled) || got != "" {
			t.Errorf("FindUserBySession = (%q, %v), want empty user ID and context.Canceled", got, err)
		}
	})
}

func TestCreateSession(t *testing.T) {
	ctx, repo := newTestRepository(t)
	userID := "test-create-session-" + rand.Text()
	hash := sha256.Sum256([]byte(rand.Text()))
	expiresAt := time.Now().In(time.FixedZone("UTC+8", 8*60*60)).Add(time.Hour).Truncate(time.Microsecond)

	if err := repo.CreateSession(ctx, hash, userID, expiresAt); err != nil {
		t.Fatalf("create session: %v", err)
	}

	t.Run("can be read back", func(t *testing.T) {
		got, err := repo.FindUserBySession(ctx, hash)
		if err != nil || got != userID {
			t.Fatalf("FindUserBySession = (%q, %v), want (%q, nil)", got, err, userID)
		}
	})

	t.Run("duplicate hash does not overwrite the session", func(t *testing.T) {
		err := repo.CreateSession(ctx, hash, userID+"-duplicate", expiresAt.Add(time.Hour))
		var mysqlErr *driver.MySQLError
		if !errors.As(err, &mysqlErr) || mysqlErr.Number != 1062 {
			t.Fatalf("duplicate insert returned %v, want MySQL duplicate key error", err)
		}

		var saved struct {
			UserID    string
			ExpiresAt time.Time
		}
		if err := repo.db.WithContext(ctx).Table("sessions").
			Select("user_id", "expires_at").Where("token_hash = ?", hash[:]).Take(&saved).Error; err != nil {
			t.Fatalf("read original session: %v", err)
		}
		if saved.UserID != userID || !saved.ExpiresAt.Equal(expiresAt) {
			t.Errorf("saved session = (%q, %s), want (%q, %s)", saved.UserID, saved.ExpiresAt, userID, expiresAt.UTC())
		}
	})
}

func TestRevokeSession(t *testing.T) {
	ctx, repo := newTestRepository(t)
	userID := "test-revoke-session-" + rand.Text()
	current := sha256.Sum256([]byte(rand.Text()))
	other := sha256.Sum256([]byte(rand.Text()))
	for _, hash := range [][32]byte{current, other} {
		if err := repo.CreateSession(ctx, hash, userID, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("create session: %v", err)
		}
	}

	readRevokedAt := func() time.Time {
		t.Helper()
		var row struct {
			RevokedAt *time.Time
		}
		if err := repo.db.WithContext(ctx).Table("sessions").Select("revoked_at").
			Where("token_hash = ?", current[:]).Take(&row).Error; err != nil {
			t.Fatalf("read revoked session row: %v", err)
		}
		if row.RevokedAt == nil {
			t.Fatal("revoked session has NULL revoked_at")
		}
		return *row.RevokedAt
	}

	if err := repo.RevokeSession(ctx, current); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	firstRevokedAt := readRevokedAt()

	// Backdate the stored timestamp so an accidental overwrite is detectable
	// even if both revocations happen within the same clock tick.
	wantRevokedAt := firstRevokedAt.Add(-time.Hour)
	if err := repo.db.WithContext(ctx).Table("sessions").Where("token_hash = ?", current[:]).
		UpdateColumn("revoked_at", wantRevokedAt).Error; err != nil {
		t.Fatalf("backdate revocation fixture: %v", err)
	}
	if err := repo.RevokeSession(ctx, current); err != nil {
		t.Fatalf("revoke session again: %v", err)
	}
	if got := readRevokedAt(); !got.Equal(wantRevokedAt) {
		t.Errorf("repeat revocation changed revoked_at to %s, want %s", got, wantRevokedAt)
	}
	if id, err := repo.FindUserBySession(ctx, current); id != "" || !errors.Is(err, auth.ErrInvalidSession) {
		t.Errorf("revoked session lookup = (%q, %v), want invalid session", id, err)
	}
	if id, err := repo.FindUserBySession(ctx, other); id != userID || err != nil {
		t.Errorf("a different session for the same user was affected: (%q, %v)", id, err)
	}
}
