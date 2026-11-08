package repository

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAnalyzeRevisionScopedGoGraph(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "calc.go"), []byte("package calc\nfunc Add(a int) int { return helper(a) }\nfunc helper(a int) int { return a + 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "calc_test.go"), []byte("package calc\nimport \"testing\"\nfunc TestAdd(t *testing.T) { Add(1) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := (Analyzer{}).Analyze(context.Background(), root, "repo", "rev-head", "abc")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Nodes) < 5 {
		t.Fatalf("nodes = %d, want files, functions, test, dependency", len(a.Nodes))
	}
	var defines, calls, tests bool
	for _, e := range a.Relationships {
		defines = defines || e.Type == "DEFINES"
		calls = calls || e.Type == "CALLS"
		tests = tests || e.Type == "TESTS"
		if e.RevisionID != "rev-head" {
			t.Fatalf("edge revision = %q", e.RevisionID)
		}
	}
	if !defines || !calls || !tests {
		t.Fatalf("graph edges missing: defines=%t calls=%t tests=%t", defines, calls, tests)
	}
	for _, n := range a.Nodes {
		if n.RevisionID != "rev-head" {
			t.Fatalf("node revision = %q", n.RevisionID)
		}
	}
}

func TestCompareDetectsChangedSymbolsByRevision(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "calc.go")
	if err := os.WriteFile(path, []byte("package calc\nfunc Add() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old, err := (Analyzer{}).Analyze(context.Background(), root, "repo", "old", "oldsha")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("package calc\nfunc Add() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	newer, err := (Analyzer{}).Analyze(context.Background(), root, "repo", "new", "newsha")
	if err != nil {
		t.Fatal(err)
	}
	_, _, changed := Compare(old, newer)
	if len(changed) == 0 {
		t.Fatal("expected changed symbol")
	}
}
