package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"example.com/xprob/internal/monitor/repo"
	"example.com/xprob/internal/monitor/service"
	"example.com/xprob/internal/store/mysql"
)

func main() {
	repository, err := openRepository()
	if err != nil {
		log.Fatal(err)
	}
	addr := os.Getenv("XPROB_HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9090"
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           newRouter(repository),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("listen on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func openRepository() (service.Repository, error) {
	addr := os.Getenv("XPROB_MYSQL_ADDR")
	if addr == "" {
		log.Print("using in-memory storage; data is not persistent")
		return repo.NewMemory(), nil
	}
	return mysql.Open(mysql.Config{
		Addr:     addr,
		User:     os.Getenv("XPROB_MYSQL_USER"),
		Password: os.Getenv("XPROB_MYSQL_PASSWORD"),
		Database: os.Getenv("XPROB_MYSQL_DATABASE"),
	})
}
