package mysql

import (
	"context"
	"os"
	"testing"
	"time"
)

func newTestRepository(t *testing.T) (context.Context, *Repository) {
	t.Helper()
	if os.Getenv("XPROB_TEST_MYSQL") != "1" {
		t.Skip("set XPROB_TEST_MYSQL=1 to run against MySQL")
	}

	repository, err := Open(Config{
		Addr:     os.Getenv("XPROB_MYSQL_ADDR"),
		User:     os.Getenv("XPROB_MYSQL_USER"),
		Password: os.Getenv("XPROB_MYSQL_PASSWORD"),
		Database: os.Getenv("XPROB_MYSQL_DATABASE"),
	})
	if err != nil {
		t.Fatalf("connect to MySQL: %v", err)
	}

	pool, err := repository.db.DB()
	if err != nil {
		t.Fatalf("get MySQL connection pool: %v", err)
	}
	// Cleanups run in reverse registration order: rollback, cancel, close.
	t.Cleanup(func() {
		if err := pool.Close(); err != nil {
			t.Errorf("close MySQL connection pool: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	tx := repository.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		t.Fatalf("begin test transaction: %v", tx.Error)
	}
	t.Cleanup(func() {
		if err := tx.Rollback().Error; err != nil {
			t.Errorf("roll back test transaction: %v", err)
		}
	})
	return ctx, &Repository{db: tx}
}
