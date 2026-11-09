package repository

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIncrementalMatchesFullAnalyze(t *testing.T) {
	root := t.TempDir()
	initGit(t, root)
	write(t, root, "a.go", "package main\nfunc Alpha() {}\n")
	write(t, root, "b.go", "package main\nfunc Beta() {}\n")
	baseSHA := commitAll(t, root, "base")

	base, err := (Analyzer{}).Analyze(context.Background(), root, "repo", "revision:base", baseSHA)
	if err != nil {
		t.Fatal(err)
	}

	write(t, root, "b.go", "package main\nfunc Beta() {}\nfunc BetaExtra() {}\n")
	write(t, root, "c.go", "package main\nfunc Gamma() {}\n")
	os.Remove(filepath.Join(root, "a.go"))
	headSHA := commitAll(t, root, "head")

	changes, err := DiffFiles(context.Background(), root, baseSHA, headSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) < 2 {
		t.Fatalf("expected file changes, got %#v", changes)
	}

	inc, err := (Analyzer{}).AnalyzeIncremental(context.Background(), root, "repo", "revision:head", headSHA, base, changes)
	if err != nil {
		t.Fatal(err)
	}
	full, err := (Analyzer{}).Analyze(context.Background(), root, "repo", "revision:head", headSHA)
	if err != nil {
		t.Fatal(err)
	}
	if problems := SnapshotConsistency(full, inc.Snapshot); len(problems) > 0 {
		t.Fatalf("incremental inconsistency: %v", problems)
	}
	if inc.ReparsedFiles < 1 || inc.DeletedFiles < 1 {
		t.Fatalf("expected reparse/delete accounting: %#v", inc)
	}
}

func initGit(t *testing.T, root string) {
	t.Helper()
	run(t, root, "git", "init")
	run(t, root, "git", "config", "user.email", "test@example.com")
	run(t, root, "git", "config", "user.name", "test")
}

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, rel), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commitAll(t *testing.T, root, message string) string {
	t.Helper()
	run(t, root, "git", "add", "-A")
	run(t, root, "git", "commit", "--allow-empty", "-m", message)
	out, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return string(bytesTrim(out))
}

func run(t *testing.T, root string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
