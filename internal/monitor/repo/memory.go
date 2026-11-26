package repo

import (
	"context"
	"sort"
	"sync"

	"example.com/xprob/internal/monitor"
)

type Memory struct {
	mu     sync.Mutex
	nextID int
	byID   map[int]monitor.Monitor
}

func NewMemory() *Memory {
	return &Memory{byID: make(map[int]monitor.Monitor)}
}

func (r *Memory) Insert(ctx context.Context, m monitor.Monitor) (monitor.Monitor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return monitor.Monitor{}, err
	}

	r.nextID++
	m.ID = r.nextID
	r.byID[m.ID] = m
	return m, nil
}

func (r *Memory) FindByID(ctx context.Context, workspaceID string, id int) (monitor.Monitor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return monitor.Monitor{}, err
	}

	m, ok := r.byID[id]
	if !ok || m.WorkspaceID != workspaceID {
		return monitor.Monitor{}, monitor.ErrNotFound
	}
	return m, nil
}

func (r *Memory) FindByWorkspaceID(ctx context.Context, workspaceID string) ([]monitor.Monitor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var monitors []monitor.Monitor
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, m := range r.byID {
		if m.WorkspaceID == workspaceID {
			monitors = append(monitors, m)
		}
	}
	sort.Slice(monitors, func(i, j int) bool {
		return monitors[i].ID < monitors[j].ID
	})
	return monitors, nil
}
