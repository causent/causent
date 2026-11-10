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

func TestVerifiedGoCallsResolveSelectorReceivers(t *testing.T) {
	root := t.TempDir()
	source := `package cacher

type A struct{}
type B struct{}
func (A) Stop() {}
func (B) Stop() {}
func callA(a A) { a.Stop() }
func callB(b B) { b.Stop() }

type Cacher struct{}
func (c *Cacher) startBackgroundResync() {}
func start(c *Cacher) { c.startBackgroundResync() }

type WaitGroup struct{}
func (WaitGroup) Wait() {}
type Owner struct { stopWg WaitGroup }
func (o *Owner) shutdown() { o.stopWg.Wait() }

type Worker interface { Stop() }
func callInterface(w Worker) { w.Stop() }
func callUnknown(x interface{}) { x.Stop() }
`
	if err := os.WriteFile(filepath.Join(root, "calls.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := (Analyzer{}).Analyze(context.Background(), root, "repo", "rev", "sha")
	if err != nil {
		t.Fatal(err)
	}

	byIdentity := map[string]domain.ProgramNode{}
	for _, node := range snapshot.Nodes {
		byIdentity[node.Identity] = node
	}
	for _, identity := range []string{
		"go:calls.go:Method:A.Stop",
		"go:calls.go:Method:B.Stop",
		"go:calls.go:Method:Cacher.startBackgroundResync",
		"go:calls.go:Method:WaitGroup.Wait",
	} {
		if byIdentity[identity].ID == "" {
			t.Fatalf("missing receiver-qualified method node %q; nodes=%#v", identity, snapshot.Nodes)
		}
	}

	callTargets := func(sourceName string) map[string]bool {
		out := map[string]bool{}
		var sourceIDs map[string]bool = map[string]bool{}
		for _, node := range snapshot.Nodes {
			if node.Name == sourceName && (node.Type == "Function" || node.Type == "Method") {
				sourceIDs[node.ID] = true
			}
		}
		for _, edge := range snapshot.Relationships {
			if edge.Type != "CALLS" || edge.Metadata["provenance"] != "verified_static_call" {
				continue
			}
			if sourceIDs[edge.SourceID] {
				out[edge.TargetID] = true
			}
		}
		return out
	}
	if targets := callTargets("callA"); !targets[byIdentity["go:calls.go:Method:A.Stop"].ID] || targets[byIdentity["go:calls.go:Method:B.Stop"].ID] {
		t.Fatalf("callA receiver resolution incorrect: %#v", targets)
	}
	if targets := callTargets("callB"); !targets[byIdentity["go:calls.go:Method:B.Stop"].ID] || targets[byIdentity["go:calls.go:Method:A.Stop"].ID] {
		t.Fatalf("callB receiver resolution incorrect: %#v", targets)
	}
	if targets := callTargets("start"); !targets[byIdentity["go:calls.go:Method:Cacher.startBackgroundResync"].ID] {
		t.Fatalf("Cacher.startBackgroundResync was not resolved: %#v", targets)
	}
	if targets := callTargets("shutdown"); !targets[byIdentity["go:calls.go:Method:WaitGroup.Wait"].ID] {
		t.Fatalf("receiver field WaitGroup.Wait was not resolved: %#v", targets)
	}
	if targets := callTargets("callInterface"); len(targets) != 0 {
		t.Fatalf("interface dispatch was incorrectly verified: %#v", targets)
	}
	if targets := callTargets("callUnknown"); len(targets) != 0 {
		t.Fatalf("unknown receiver was incorrectly verified: %#v", targets)
	}
}
