package repository

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/causent/malenia/internal/domain"
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

func TestGoSymbolsUseASTDeclarationRanges(t *testing.T) {
	root := t.TempDir()
	source := `package cacher

type Config struct {
	 Name string
}

type Store interface {
	 Get() error
}

func WithCodec[T any](codec T,
	 option string) error {
	 if option == "" { return nil }
	 return nil
}

func newTimeBucketWatchers() {
	for i := 0; i < 2; i++ { println(i) }
}

func after() {}
`
	if err := os.WriteFile(filepath.Join(root, "cacher.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := (Analyzer{}).Analyze(context.Background(), root, "repo", "rev", "sha")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]domain.ProgramNode{}
	for _, n := range snapshot.Nodes {
		if n.FilePath == "cacher.go" {
			byName[n.Name] = n
		}
	}
	for _, name := range []string{"Config", "Store", "WithCodec", "newTimeBucketWatchers", "after"} {
		if byName[name].StartLine == 0 {
			t.Fatalf("missing symbol %s", name)
		}
	}
	if byName["Config"].EndLine != 5 || byName["Store"].EndLine != 9 {
		t.Fatalf("type ranges incorrect: config=%+v store=%+v", byName["Config"], byName["Store"])
	}
	if byName["WithCodec"].StartLine != 11 || byName["WithCodec"].EndLine != 15 {
		t.Fatalf("function range incorrect: %+v", byName["WithCodec"])
	}
	if byName["newTimeBucketWatchers"].EndLine != 19 || byName["after"].StartLine != 21 || byName["newTimeBucketWatchers"].EndLine >= byName["after"].StartLine {
		t.Fatalf("function ranges overlap: watcher=%+v after=%+v", byName["newTimeBucketWatchers"], byName["after"])
	}
}
