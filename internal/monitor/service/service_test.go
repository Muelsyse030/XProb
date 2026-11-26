package service_test

import (
	"context"
	"errors"
	"testing"

	"example.com/xprob/internal/monitor"
	"example.com/xprob/internal/monitor/repo"
	"example.com/xprob/internal/monitor/service"
)

func TestCreateDraftTrimsName(t *testing.T) {
	s := service.New(repo.NewMemory())
	draft, err := s.CreateDraft(context.Background(), "demo", "  首页 API  ")
	if err != nil {
		t.Fatal(err)
	}
	if draft.Name != "首页 API" || draft.Status != monitor.StatusDraft {
		t.Errorf("草稿名称或状态不正确：%+v", draft)
	}
}

func TestCreateDraftRejectsBlankName(t *testing.T) {
	s := service.New(repo.NewMemory())
	_, err := s.CreateDraft(context.Background(), "demo", " \t ")
	if !errors.Is(err, service.ErrNameRequired) {
		t.Errorf("错误 = %v，期望 %v", err, service.ErrNameRequired)
	}
}
