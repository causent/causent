package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfiguredAgentRequiresExplicitGatewaySettings(t *testing.T) {
	t.Setenv("MALENIA_GATEWAY_ENDPOINT", "")
	t.Setenv("MALENIA_GATEWAY_MODEL", "")
	if _, err := configuredAgent(); err == nil {
		t.Fatal("expected missing gateway endpoint error")
	}
	t.Setenv("MALENIA_GATEWAY_ENDPOINT", "http://gateway.test")
	if _, err := configuredAgent(); err == nil {
		t.Fatal("expected missing gateway model error")
	}
	t.Setenv("MALENIA_GATEWAY_MODEL", "test-model")
	client, err := configuredAgent()
	if err != nil || client.Endpoint != "http://gateway.test" || client.Model != "test-model" {
		t.Fatalf("unexpected configured agent: %#v, %v", client, err)
	}
}

func TestLoadRepoConfig(t *testing.T) {
	dir := t.TempDir()
	body := `command: go test ./...
base: origin/main
attempts: 5
timeout: 2m
executor: docker
image: golang:1.26
agent: true
probes:
  - go version
`
	if err := os.WriteFile(filepath.Join(dir, ".malenia.yml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadRepoConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command != "go test ./..." || cfg.Base != "origin/main" || cfg.Attempts != 5 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.Timeout != "2m" || cfg.Executor != "docker" || cfg.Image != "golang:1.26" || !cfg.Agent {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if len(cfg.Probes) != 1 || cfg.Probes[0] != "go version" {
		t.Fatalf("unexpected probes: %v", cfg.Probes)
	}
}

func TestLoadRepoConfigMissingIsOK(t *testing.T) {
	cfg, err := loadRepoConfig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Command != "" || cfg.Attempts != 0 || len(cfg.Probes) != 0 {
		t.Fatalf("expected empty config, got %+v", cfg)
	}
}

func TestLoadRepoConfigRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".malenia.yml"), []byte("comand: go test ./...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRepoConfig(dir); err == nil {
		t.Fatal("expected unknown key error")
	}
}

func TestLoadRepoConfigRejectsBadTimeout(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".malenia.yml"), []byte("timeout: soon\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRepoConfig(dir); err == nil {
		t.Fatal("expected timeout error")
	}
}
