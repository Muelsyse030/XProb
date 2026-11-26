package mysql

import (
	"context"
	"errors"
	"fmt"
	"time"

	"example.com/xprob/internal/monitor"
	"example.com/xprob/internal/monitor/service"
	driver "github.com/go-sql-driver/mysql"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type Config struct {
	Addr     string
	User     string
	Password string
	Database string
}

type Repository struct {
	db *gorm.DB
}

var _ service.Repository = (*Repository)(nil)

func Open(cfg Config) (*Repository, error) {
	if cfg.Addr == "" || cfg.User == "" || cfg.Password == "" || cfg.Database == "" {
		return nil, errors.New("MySQL address, user, password and database are required")
	}

	dsn := driver.NewConfig()
	dsn.Net = "tcp"
	dsn.Addr = cfg.Addr
	dsn.User = cfg.User
	dsn.Passwd = cfg.Password
	dsn.DBName = cfg.Database
	dsn.ParseTime = true
	dsn.Loc = time.UTC
	dsn.Params = map[string]string{"time_zone": "'+00:00'"}
	dsn.Timeout = 5 * time.Second
	dsn.ReadTimeout = 5 * time.Second
	dsn.WriteTimeout = 5 * time.Second

	db, err := gorm.Open(gormmysql.Open(dsn.FormatDSN()), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open MySQL: %w", err)
	}
	return &Repository{db: db}, nil
}

// monitorRow is the MySQL representation; the domain type does not depend on GORM.
type monitorRow struct {
	ID          int `gorm:"primaryKey;autoIncrement"`
	WorkspaceID string
	Name        string
	Status      string
}

func (monitorRow) TableName() string { return "monitors" }

func (m monitorRow) toMonitor() monitor.Monitor {
	return monitor.Monitor{ID: m.ID, WorkspaceID: m.WorkspaceID, Name: m.Name, Status: m.Status}
}

func (r *Repository) Insert(ctx context.Context, m monitor.Monitor) (monitor.Monitor, error) {
	row := monitorRow{WorkspaceID: m.WorkspaceID, Name: m.Name, Status: m.Status}
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		return monitor.Monitor{}, err
	}
	return row.toMonitor(), nil
}

func (r *Repository) FindByID(ctx context.Context, workspaceID string, id int) (monitor.Monitor, error) {
	var row monitorRow
	err := r.db.WithContext(ctx).Where("workspace_id = ? AND id = ?", workspaceID, id).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return monitor.Monitor{}, monitor.ErrNotFound
	}
	if err != nil {
		return monitor.Monitor{}, err
	}
	return row.toMonitor(), nil
}

func (r *Repository) FindByWorkspaceID(ctx context.Context, workspaceID string) ([]monitor.Monitor, error) {
	var rows []monitorRow
	err := r.db.WithContext(ctx).Where("workspace_id = ?", workspaceID).Order("id ASC").Find(&rows).Error
	if err != nil {
		return nil, err
	}
	monitors := make([]monitor.Monitor, 0, len(rows))
	for _, row := range rows {
		monitors = append(monitors, row.toMonitor())
	}
	return monitors, nil
}
