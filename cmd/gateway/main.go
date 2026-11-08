package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/causent/malenia/internal/gateway"
	"github.com/causent/malenia/internal/persistence"
)

func main() {
	config := gateway.ConfigFromEnvironment()
	// Open SQLite store for SSE event streaming and artifact access
	dbPath := os.Getenv("MALENIA_DB")
	if dbPath == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			home = "/Users/yashbahuguna"
		}
		dbPath = home + "/.malenia/investigations.db"
	}
	db, err := persistence.Open(dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()
	config.Store = db
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Printf("malenia gateway listening on %s (provider=%s model=%s)\n", config.ListenAddr, config.Provider, config.Model)
	if err := gateway.NewServer(config).ListenAndServe(ctx); err != nil {
		fmt.Println(err)
	}
}
