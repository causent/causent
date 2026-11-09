package localization

import (
	"testing"
	"time"

	"github.com/causent/malenia/internal/domain"
	programrepo "github.com/causent/malenia/internal/repository"
)

func TestGenerateExpandsToUnchangedCalleeAndSharesCandidate(t *testing.T) {
	file := domain.ProgramNode{ID: "file", Type: "File", FilePath: "pkg.go", RevisionID: "rev", RepositoryID: "repo"}
	test := domain.ProgramNode{ID: "test", Type: "Test", Name: "TestFailure", FilePath: "pkg_test.go", StartLine: 1, EndLine: 10, RevisionID: "rev", RepositoryID: "repo", Identity: "go:pkg_test.go:Test:TestFailure"}
	changed := domain.ProgramNode{ID: "changed", Type: "Function", Name: "Changed", FilePath: "pkg.go", StartLine: 1, EndLine: 10, RevisionID: "rev", RepositoryID: "repo", Identity: "go:pkg.go:Function:Changed", Changed: true}
	unchanged := domain.ProgramNode{ID: "utility", Type: "Function", Name: "Utility", FilePath: "utility.go", StartLine: 1, EndLine: 10, RevisionID: "rev", RepositoryID: "repo", Identity: "go:utility.go:Function:Utility"}
	s := programrepo.Snapshot{
		RepositoryID: "repo",
		RevisionID:   "rev",
		Nodes:        []domain.ProgramNode{file, test, changed, unchanged},
		Relationships: []domain.Relationship{
			{ID: "r1", SourceID: "test", SourceType: "Test", TargetID: "changed", TargetType: "Function", Type: "TESTS", RevisionID: "rev", CreatedAt: time.Now()},
			{ID: "r2", SourceID: "changed", SourceType: "Function", TargetID: "utility", TargetType: "Function", Type: "CALLS", RevisionID: "rev", CreatedAt: time.Now()},
		},
	}
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

func TestGenerateObservedCandidatesWithoutSnapshot(t *testing.T) {
	frames := []Frame{{File: "pkg/handler.go", Line: 142, FailureIDs: []string{"failure-1"}}}
	candidates, relations := GenerateObserved(frames, Input{
		InvestigationID: "inv",
		RepositoryID:    "repo",
		RevisionID:      "revision:head",
		EvidenceIDs:     []domain.ID{"e1"},
		MaxCandidates:   10,
	})
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want 1", len(candidates))
	}
	candidate := candidates[0]
	if candidate.Location.LocationType != "observed_frame" {
		t.Fatalf("location type = %q, want observed_frame", candidate.Location.LocationType)
	}
	if candidate.Location.FilePath != "pkg/handler.go" || candidate.Location.StartLine != 142 {
		t.Fatalf("unexpected observed location: %#v", candidate.Location)
	}
	if len(candidate.SupportingEvidenceIDs) != 1 || candidate.SupportingEvidenceIDs[0] != "e1" {
		t.Fatalf("candidate evidence = %#v", candidate.SupportingEvidenceIDs)
	}
	if len(relations) != 1 || relations[0].Type != "MANIFESTED_AT" {
		t.Fatalf("relations = %#v", relations)
	}
}

func TestGenerateObservedCandidateIDsAreInvestigationScoped(t *testing.T) {
	frame := []Frame{{File: "pkg/handler.go", Line: 142}}
	first, _ := GenerateObserved(frame, Input{InvestigationID: "inv-1", RepositoryID: "repo", RevisionID: "rev", MaxCandidates: 10})
	second, _ := GenerateObserved(frame, Input{InvestigationID: "inv-2", RepositoryID: "repo", RevisionID: "rev", MaxCandidates: 10})
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("expected one candidate per investigation: %#v %#v", first, second)
	}
	if first[0].ID == second[0].ID {
		t.Fatalf("candidate IDs collided: %q", first[0].ID)
	}
}
