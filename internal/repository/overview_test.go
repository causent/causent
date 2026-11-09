package repository

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildOverviewDetectsLanguagesAndManifests(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(path, body string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("go.mod", "module example\n")
	mustWrite("main.go", "package main\n")
	mustWrite("pkg/util.py", "def f():\n  return 1\n")
	mustWrite("tests/test_util.py", "def test_f():\n  assert True\n")
	mustWrite("package.json", "{}\n")

	ov, err := BuildOverview(context.Background(), root, "repo", "rev", "sha")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(ov.Languages, "go") || !contains(ov.Languages, "python") || !contains(ov.Languages, "javascript") {
		t.Fatalf("languages=%v", ov.Languages)
	}
	if !contains(ov.BuildSystems, "go") || !contains(ov.Manifests, "go.mod") {
		t.Fatalf("build=%v manifests=%v", ov.BuildSystems, ov.Manifests)
	}
	if ov.FileCounts["go"] < 1 || ov.FileCounts["python"] < 1 {
		t.Fatalf("file counts=%v", ov.FileCounts)
	}
	if len(ov.CoverageNotes) == 0 {
		t.Fatal("expected coverage notes")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
