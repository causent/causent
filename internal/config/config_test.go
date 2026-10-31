package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndValidateConfig(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	if err := os.WriteFile(path, []byte(`{"database_path":"db.sqlite","authorized_roots":["`+root+`"],"budget":4}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Budget != 4 || cfg.DatabasePath != "db.sqlite" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestValidateRejectsUnsafeBounds(t *testing.T) {
	cfg := Defaults()
	cfg.MaxOutput = 17 << 20
	if err := Validate(cfg); err == nil {
		t.Fatal("expected max output validation error")
	}
}
