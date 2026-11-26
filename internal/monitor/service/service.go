package service

import (
	"context"
	"errors"
	"strings"

	"example.com/xprob/internal/monitor"
)

var ErrNameRequired = errors.New("name is required")

type Repository interface {
	Insert(ctx context.Context, m monitor.Monitor) (monitor.Monitor, error)
	FindByID(ctx context.Context, workspaceID string, id int) (monitor.Monitor, error)
	FindByWorkspaceID(ctx context.Context, workespace string) ([]monitor.Monitor, error)
}

type Service struct {
	repo Repository
}

func New(repo Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) CreateDraft(ctx context.Context, workspaceID, name string) (monitor.Monitor, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return monitor.Monitor{}, ErrNameRequired
	}

	return s.repo.Insert(ctx, monitor.Monitor{
		WorkspaceID: workspaceID,
		Name:        name,
		Status:      monitor.StatusDraft,
	})
}

func (s *Service) GetMonitor(ctx context.Context, workspaceID string, id int) (monitor.Monitor, error) {
	return s.repo.FindByID(ctx, workspaceID, id)
}

func (s *Service) GetMonitorByWorkspaceID(ctx context.Context, workespace string) ([]monitor.Monitor, error) {
	return s.repo.FindByWorkspaceID(ctx, workespace)
}
