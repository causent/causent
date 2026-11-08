package localization

import (
	"github.com/causent/causent/internal/domain"
	programrepo "github.com/causent/causent/internal/repository"
	"testing"
	"time"
)

func TestGenerateExpandsToUnchangedCalleeAndSharesCandidate(t *testing.T) {
	file := domain.ProgramNode{ID: "file", Type: "File", FilePath: "pkg.go", RevisionID: "rev", RepositoryID: "repo"}
	test := domain.ProgramNode{ID: "test", Type: "Test", Name: "TestFailure", FilePath: "pkg_test.go", StartLine: 1, EndLine: 10, RevisionID: "rev", RepositoryID: "repo", Identity: "go:pkg_test.go:Test:TestFailure"}
	changed := domain.ProgramNode{ID: "changed", Type: "Function", Name: "Changed", FilePath: "pkg.go", StartLine: 1, EndLine: 10, RevisionID: "rev", RepositoryID: "repo", Identity: "go:pkg.go:Function:Changed", Changed: true}
	unchanged := domain.ProgramNode{ID: "utility", Type: "Function", Name: "Utility", FilePath: "utility.go", StartLine: 1, EndLine: 10, RevisionID: "rev", RepositoryID: "repo", Identity: "go:utility.go:Function:Utility"}
	s := programrepo.Snapshot{RepositoryID: "repo", RevisionID: "rev", Nodes: []domain.ProgramNode{file, test, changed, unchanged}, Relationships: []domain.Relationship{{ID: "r1", SourceID: "test", SourceType: "Test", TargetID: "changed", TargetType: "Function", Type: "TESTS", RevisionID: "rev", CreatedAt: time.Now()}, {ID: "r2", SourceID: "changed", SourceType: "Function", TargetID: "utility", TargetType: "Function", Type: "CALLS", RevisionID: "rev", CreatedAt: time.Now()}}}
	got, rels := Generate(s, Input{InvestigationID: "inv", FailureIDs: []string{"failure-1"}, FailureText: "TestFailure", EvidenceIDs: []domain.ID{"ev-1"}, MaxDepth: 2})
	if len(got) < 2 {
		t.Fatalf("candidates = %d, want changed and expanded utility", len(got))
	}
	foundUtility := false
	for _, c := range got {
		if c.Location.SymbolIdentity == unchanged.Identity {
			foundUtility = true
			if c.Score.DependencyRelevance == 0 {
				t.Fatal("expanded utility lacks dependency relevance")
			}
		}
	}
	if !foundUtility {
		t.Fatal("unchanged utility was not discovered")
	}
	if len(rels) == 0 {
		t.Fatal("expected failure relationships")
	}
}
