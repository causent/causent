// Package config contains the small, environment-friendly Hades configuration
// surface shared by command-line and MCP entry points.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Config struct {
	DatabasePath    string        `json:"database_path"`
	ArtifactPath    string        `json:"artifact_path"`
	AuthorizedRoots []string      `json:"authorized_roots"`
	AllowedCommands []string      `json:"allowed_commands"`
	Timeout         time.Duration `json:"timeout"`
	Budget          int           `json:"budget"`
	MaxOutput       int           `json:"max_output"`
	LogLevel        string        `json:"log_level"`
}

func Defaults() Config {
	home, _ := os.UserHomeDir()
	db := filepath.Join(home, ".hades", "investigations.db")
	return Config{
		DatabasePath: db, ArtifactPath: filepath.Join(filepath.Dir(db), "artifacts"),
		Timeout: 10 * time.Minute, Budget: 20, MaxOutput: 64 << 10,
		LogLevel: "info",
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config: %w", err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config: %w", err)
		}
	}
	applyEnv(&cfg)
	if err := Validate(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func Validate(cfg Config) error {
	if cfg.DatabasePath == "" {
		return errors.New("database_path is required")
	}
	if cfg.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if cfg.Budget <= 0 {
		return errors.New("budget must be positive")
	}
	if cfg.MaxOutput <= 0 || cfg.MaxOutput > 16<<20 {
		return errors.New("max_output must be between 1 and 16777216")
	}
	for _, root := range cfg.AuthorizedRoots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("authorized root is not a directory: %s", root)
		}
	}
	return nil
}

func applyEnv(cfg *Config) {
	if value := os.Getenv("HADES_DB"); value != "" {
		cfg.DatabasePath = value
	}
	if value := os.Getenv("HADES_ARTIFACTS"); value != "" {
		cfg.ArtifactPath = value
	}
	if value := os.Getenv("HADES_ROOTS"); value != "" {
		cfg.AuthorizedRoots = filepath.SplitList(value)
	}
	if value := os.Getenv("HADES_COMMANDS"); value != "" {
		cfg.AllowedCommands = filepath.SplitList(value)
	}
	if value := os.Getenv("HADES_TIMEOUT"); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			cfg.Timeout = parsed
		}
	}
	if value := os.Getenv("HADES_BUDGET"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			cfg.Budget = parsed
		}
	}
}
