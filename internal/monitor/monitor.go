package monitor

import "errors"

const StatusDraft = "draft"

var ErrNotFound = errors.New("monitor not found")

type Monitor struct {
	ID          int
	WorkspaceID string
	Name        string
	Status      string
}
