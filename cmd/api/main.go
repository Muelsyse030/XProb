package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"example.com/xprob/internal/auth"
	"example.com/xprob/internal/monitor/repo"
	"example.com/xprob/internal/monitor/service"
	"example.com/xprob/internal/store/mysql"
)

func main() {
	repository, authStorage, err := openRepositories()
	if err != nil {
		log.Fatal(err)
	}
	access, err := configureAuth(context.Background(), authStorage)
	if err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("XPROB_HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9090"
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           newRouter(repository, access),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("listen on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

type authStore interface {
	auth.SessionStore
	auth.RoleReader
}

func openRepositories() (service.Repository, authStore, error) {
	addr := os.Getenv("XPROB_MYSQL_ADDR")
	if addr == "" {
		log.Print("using in-memory storage; data is not persistent")
		return repo.NewMemory(), nil, nil
	}
	store, err := mysql.Open(mysql.Config{
		Addr:     addr,
		User:     os.Getenv("XPROB_MYSQL_USER"),
		Password: os.Getenv("XPROB_MYSQL_PASSWORD"),
		Database: os.Getenv("XPROB_MYSQL_DATABASE"),
	})
	if err != nil {
		return nil, nil, err
	}
	return store, store, nil
}

func configureAuth(ctx context.Context, store authStore) (routerAuth, error) {
	cfg := auth.OIDCConfig{
		Issuer:       os.Getenv("XPROB_OIDC_ISSUER"),
		ClientID:     os.Getenv("XPROB_OIDC_CLIENT_ID"),
		ClientSecret: os.Getenv("XPROB_OIDC_CLIENT_SECRET"),
		Origin:       os.Getenv("XPROB_PUBLIC_ORIGIN"),
	}
	if cfg == (auth.OIDCConfig{}) {
		log.Print("OIDC not configured; monitor endpoints require authentication")
		return routerAuth{}, nil
	}
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.Origin == "" {
		return routerAuth{}, errors.New("all XPROB_OIDC_* values and XPROB_PUBLIC_ORIGIN must be configured together")
	}
	if store == nil {
		return routerAuth{}, errors.New("OIDC requires the MySQL session and workspace membership store")
	}
	login, err := auth.NewLogin(ctx, cfg, store)
	if err != nil {
		return routerAuth{}, err
	}
	return routerAuth{sessions: store, roles: store, origin: cfg.Origin, login: login}, nil
}
