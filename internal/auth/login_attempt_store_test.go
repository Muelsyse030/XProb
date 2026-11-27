package auth

import (
	"strconv"
	"testing"
	"time"
)

func newLoginAttemptStoreFixture() (*memoryLoginAttempts, loginAttempt, [32]byte) {
	attempt := loginAttempt{
		state:        "login-state",
		nonce:        "login-nonce",
		codeVerifier: "login-verifier",
		expiresAt:    time.Date(2030, time.January, 2, 12, 0, 0, 0, time.UTC),
	}
	browserHash := [32]byte{1}
	store := newMemoryLoginAttempts()
	store.save(attempt, browserHash, attempt.expiresAt.Add(-time.Minute))
	return store, attempt, browserHash
}

func TestConsumeLoginAttemptOnlyOnceForMatchingBrowser(t *testing.T) {
	store, attempt, browserHash := newLoginAttemptStoreFixture()
	now := attempt.expiresAt.Add(-time.Minute)

	if _, ok := store.consume("unknown-state", browserHash, now); ok {
		t.Fatal("unknown state was accepted")
	}
	if _, ok := store.consume(attempt.state, [32]byte{2}, now); ok {
		t.Fatal("attempt was accepted from another browser")
	}
	got, ok := store.consume(attempt.state, browserHash, now)
	if !ok || got != attempt {
		t.Fatal("correct browser did not receive the original attempt")
	}
	if _, ok := store.consume(attempt.state, browserHash, now); ok {
		t.Fatal("same attempt was accepted twice")
	}
	if _, exists := store.byState[attempt.state]; exists {
		t.Error("consumed attempt was not removed from the map")
	}
}

func TestConsumeLoginAttemptExpiration(t *testing.T) {
	cases := []struct {
		name   string
		offset time.Duration
		wantOK bool
	}{
		{"just before expiry", -time.Nanosecond, true},
		{"exactly at expiry", 0, false},
		{"after expiry", time.Nanosecond, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, attempt, browserHash := newLoginAttemptStoreFixture()
			_, ok := store.consume(attempt.state, browserHash, attempt.expiresAt.Add(tc.offset))
			if ok != tc.wantOK {
				t.Errorf("consume accepted = %t, want %t", ok, tc.wantOK)
			}
		})
	}
}

func TestConsumeLoginAttemptConcurrently(t *testing.T) {
	store, attempt, browserHash := newLoginAttemptStoreFixture()
	now := attempt.expiresAt.Add(-time.Minute)
	const callers = 16
	start := make(chan struct{})
	results := make(chan bool, callers)
	for range callers {
		go func() {
			<-start
			_, ok := store.consume(attempt.state, browserHash, now)
			results <- ok
		}()
	}
	close(start)

	successes := 0
	for range callers {
		if <-results {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("%d concurrent calls succeeded, want exactly 1", successes)
	}
}

func TestLoginAttemptStoreRejectsDuplicatesAndPrunesExpiredAttempts(t *testing.T) {
	now := time.Unix(1800000000, 0)
	store := newMemoryLoginAttempts()
	first := loginAttempt{state: "first", expiresAt: now.Add(time.Minute)}
	firstHash := [32]byte{1}
	if !store.save(first, firstHash, now) || store.save(first, [32]byte{2}, now) {
		t.Fatal("store must accept a new attempt and reject a duplicate state")
	}
	if _, ok := store.consume(first.state, [32]byte{2}, now); ok {
		t.Fatal("duplicate save replaced the original browser binding")
	}
	second := loginAttempt{state: "second", expiresAt: now.Add(2 * time.Minute)}
	if !store.save(second, firstHash, first.expiresAt) {
		t.Fatal("could not save the second attempt")
	}
	if len(store.byState) != 1 {
		t.Error("save did not remove expired entries")
	}
}

func TestLoginAttemptStoreHasCapacityLimit(t *testing.T) {
	now := time.Unix(1800000000, 0)
	store := newMemoryLoginAttempts()
	for i := range maxPendingLoginAttempts {
		attempt := loginAttempt{state: strconv.Itoa(i), expiresAt: now.Add(time.Minute)}
		if !store.save(attempt, [32]byte{1}, now) {
			t.Fatalf("save failed before capacity was reached at entry %d", i)
		}
	}
	if store.save(loginAttempt{state: "extra", expiresAt: now.Add(time.Minute)}, [32]byte{1}, now) {
		t.Fatal("save succeeded beyond capacity")
	}
}
