package auth

import (
	"crypto/subtle"
	"sync"
	"time"
)

const maxPendingLoginAttempts = 1024

type storedLoginAttempt struct {
	attempt          loginAttempt
	browserTokenHash [32]byte
}

type memoryLoginAttempts struct {
	mu      sync.Mutex
	byState map[string]storedLoginAttempt
}

func newMemoryLoginAttempts() *memoryLoginAttempts {
	return &memoryLoginAttempts{
		byState: make(map[string]storedLoginAttempt),
	}
}

func (s *memoryLoginAttempts) save(attempt loginAttempt, browserTokenHash [32]byte, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for state, pending := range s.byState {
		if !now.Before(pending.attempt.expiresAt) {
			delete(s.byState, state)
		}
	}
	if _, exists := s.byState[attempt.state]; exists || len(s.byState) >= maxPendingLoginAttempts ||
		attempt.state == "" || !now.Before(attempt.expiresAt) {
		return false
	}
	s.byState[attempt.state] = storedLoginAttempt{
		attempt:          attempt,
		browserTokenHash: browserTokenHash,
	}
	return true
}

func (s *memoryLoginAttempts) consume(state string, browserTokenHash [32]byte, now time.Time) (loginAttempt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	buf, ok := s.byState[state]
	if !ok {
		return loginAttempt{}, false
	}
	if !now.Before(buf.attempt.expiresAt) {
		delete(s.byState, state)
		return loginAttempt{}, false
	}
	if subtle.ConstantTimeCompare(buf.browserTokenHash[:], browserTokenHash[:]) != 1 {
		return loginAttempt{}, false
	}
	delete(s.byState, state)
	return buf.attempt, true
}
