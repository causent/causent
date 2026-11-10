package diagnosis

import (
	"testing"

	"github.com/causent/malenia/internal/domain"
	programrepo "github.com/causent/malenia/internal/repository"
)

func TestBuildExecutionPathsDoesNotTraverseStructuralRelationships(t *testing.T) {
	testNode := domain.ProgramNode{ID: "test", Type: "Test", Name: "TestWatch", FilePath: "watcher_test.go", StartLine: 1, EndLine: 10}
	unrelated := domain.ProgramNode{ID: "unrelated", Type: "Function", Name: "Run", FilePath: "allocation_manager.go", StartLine: 20, EndLine: 30}
	candidate := domain.CandidateLocation{ID: "candidate:unrelated", Location: domain.CodeLocation{SymbolIdentity: unrelated.Identity}}
	snapshot := programSnapshotForPathTest([]domain.ProgramNode{testNode, unrelated}, []domain.Relationship{{ID: "reference", SourceID: "test", TargetID: "unrelated", Type: "REFERENCES"}})
	paths, _ := buildExecutionPaths("inv", snapshot, []domain.CandidateLocation{candidate}, "TestWatch failed", []string{"failure"}, nil)
	if len(paths) != 0 {
		t.Fatalf("structural relationship became execution path: %#v", paths)
	}
}

func TestBuildExecutionPathsLabelsCallRelationshipsAsInferred(t *testing.T) {
	testNode := domain.ProgramNode{ID: "test", Type: "Test", Name: "TestWatch", FilePath: "watcher_test.go"}
	production := domain.ProgramNode{ID: "prod", Type: "Function", Name: "Run", FilePath: "cache.go"}
	candidate := domain.CandidateLocation{ID: "candidate:prod", Location: domain.CodeLocation{SymbolIdentity: production.Identity}}
	snapshot := programSnapshotForPathTest([]domain.ProgramNode{testNode, production}, []domain.Relationship{{ID: "call", SourceID: "test", TargetID: "prod", Type: "CALLS", Metadata: map[string]string{"provenance": "verified_static_call"}}})
	paths, _ := buildExecutionPaths("inv", snapshot, []domain.CandidateLocation{candidate}, "TestWatch failed", []string{"failure"}, nil)
	if len(paths) != 1 || paths[0].Status != "inferred_call_path" {
		t.Fatalf("call relationship not represented as inferred path: %#v", paths)
	}
}

func TestBuildExecutionPathsRejectsUnverifiedInferredRelationship(t *testing.T) {
	testNode := domain.ProgramNode{ID: "test", Type: "Test", Name: "TestWatch", FilePath: "watcher_test.go"}
	production := domain.ProgramNode{ID: "prod", Type: "Function", Name: "Run", FilePath: "cache.go"}
	candidate := domain.CandidateLocation{ID: "candidate:prod", Location: domain.CodeLocation{SymbolIdentity: production.Identity, Provenance: "inferred_caller"}}
	snapshot := programSnapshotForPathTest([]domain.ProgramNode{testNode, production}, []domain.Relationship{{ID: "call", SourceID: "test", TargetID: "prod", Type: "CALLS", Metadata: map[string]string{"provenance": "inferred_caller"}}})
	paths, _ := buildExecutionPaths("inv", snapshot, []domain.CandidateLocation{candidate}, "TestWatch failed", []string{"failure"}, nil)
	if len(paths) != 0 {
		t.Fatalf("unverified relationship became execution path: %#v", paths)
	}
}

func programSnapshotForPathTest(nodes []domain.ProgramNode, relationships []domain.Relationship) programrepo.Snapshot {
	return programrepo.Snapshot{Nodes: nodes, Relationships: relationships}
}
