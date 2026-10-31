package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/Yashbhu/Hades/internal/engine"
	"github.com/Yashbhu/Hades/internal/execution"
	"github.com/Yashbhu/Hades/internal/mcp"
	"github.com/Yashbhu/Hades/internal/persistence"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	fs := flag.NewFlagSet("hades-mcp", flag.ExitOnError)
	db := fs.String("db", "hades.db", "SQLite database path")
	root := fs.String("root", "", "authorized repository root (required)")
	fs.Parse(os.Args[1:])
	if *root == "" {
		fmt.Fprintln(os.Stderr, "-root is required")
		os.Exit(2)
	}
	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	store, err := persistence.Open(*db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer store.Close()
	artifactRoot := filepath.Join(filepath.Dir(*db), "artifacts")
	policy := execution.Policy{
		AllowedCommands:    map[string]bool{"python": true, "python3": true, "pytest": true},
		AllowedDirs:        map[string]bool{absRoot: true},
		AllowedDirPrefixes: []string{absRoot, os.TempDir()},
		AllowedEnviron:     map[string]bool{},
		MaxOutput:          64 << 10,
		Timeout:            10 * time.Minute,
	}
	server, err := mcp.NewServer(mcp.Config{
		Store: store, Executor: execution.NewLocalExecutor(policy, execution.NewArtifactFactory(artifactRoot)),
		Provider: engine.HeuristicProvider{}, AuthorizedRoots: []string{absRoot},
		AllowedCommands: policy.AllowedCommands,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := server.ServeStdio(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
