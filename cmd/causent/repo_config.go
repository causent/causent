package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// repoConfig is the subset of .causent.yml that `causent diagnose` understands.
// Command-line flags always win over these values.
type repoConfig struct {
	Command  string       `yaml:"command"`
	Base     string       `yaml:"base"`
	Good     string       `yaml:"good"`
	Attempts int          `yaml:"attempts"`
	Timeout  string       `yaml:"timeout"`
	Executor string       `yaml:"executor"`
	Image    string       `yaml:"image"`
	Agent    bool         `yaml:"agent"`
	Probes   []string     `yaml:"probes"`
	Repair   repairConfig `yaml:"repair"`
}

type repairConfig struct {
	MaxAttempts int `yaml:"max_attempts"`
}

var repoConfigNames = []string{".causent.yml", ".causent.yaml"}

// loadRepoConfig reads the first .causent.yml found in the repository root.
// A missing file is not an error.
func loadRepoConfig(repoPath string) (repoConfig, error) {
	for _, name := range repoConfigNames {
		path := filepath.Join(repoPath, name)
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return repoConfig{}, fmt.Errorf("read %s: %w", name, err)
		}
		var cfg repoConfig
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(&cfg); err != nil {
			return repoConfig{}, fmt.Errorf("parse %s: %w", name, err)
		}
		if cfg.Attempts < 0 {
			return repoConfig{}, fmt.Errorf("parse %s: attempts must be positive", name)
		}
		if cfg.Repair.MaxAttempts < 0 {
			return repoConfig{}, fmt.Errorf("parse %s: repair.max_attempts must be positive", name)
		}
		if cfg.Timeout != "" {
			if _, err := time.ParseDuration(cfg.Timeout); err != nil {
				return repoConfig{}, fmt.Errorf("parse %s: timeout: %w", name, err)
			}
		}
		return cfg, nil
	}
	return repoConfig{}, nil
}
