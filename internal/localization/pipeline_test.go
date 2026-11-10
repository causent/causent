package localization

import (
	"testing"
	"time"

	"github.com/causent/malenia/internal/domain"
	programrepo "github.com/causent/malenia/internal/repository"
)

func TestGenerateDoesNotPromoteUnverifiedRelationships(t *testing.T) {
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
	if len(got) != 1 {
		t.Fatalf("candidates = %d, want only the directly supported candidate", len(got))
	}
	if got[0].Location.SymbolIdentity != test.Identity || len(rels) == 0 {
		t.Fatalf("unexpected candidates/relationships: %#v %#v", got, rels)
	}
}

func TestGenerateObservedCandidatesWithoutSnapshot(t *testing.T) {
	frames := []Frame{{File: "pkg/handler.go", Line: 142, FailureIDs: []string{"failure-1"}, EvidenceIDs: []domain.ID{"e1"}}}
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

func TestGenerateMapsFrameToOnlyItsEnclosingSymbol(t *testing.T) {
	snapshot := programrepo.Snapshot{RepositoryID: "repo", RevisionID: "rev", Nodes: []domain.ProgramNode{
		{ID: "outer", Type: "Function", Name: "Outer", FilePath: "cache.go", StartLine: 10, EndLine: 30, Identity: "outer"},
		{ID: "inner", Type: "Function", Name: "Inner", FilePath: "cache.go", StartLine: 20, EndLine: 22, Identity: "inner"},
	}}
	got, _ := Generate(snapshot, Input{InvestigationID: "inv", RepositoryID: "repo", RevisionID: "rev", StackFrames: []Frame{{File: "cache.go", Line: 21, EvidenceIDs: []domain.ID{"frame"}}}, MaxCandidates: 10})
	if len(got) != 1 || got[0].Location.SymbolIdentity != "inner" {
		t.Fatalf("frame mapped to broad or multiple symbols: %#v", got)
	}
	if got[0].Score.ExecutionRelevance == 0 || got[0].Location.Provenance != "enclosing_symbol" {
		t.Fatalf("direct frame attribution missing: %#v", got[0])
	}
}

func TestPackageAndChangedEvidenceDoNotCreateExecutionScore(t *testing.T) {
	snapshot := programrepo.Snapshot{RepositoryID: "repo", RevisionID: "rev", Nodes: []domain.ProgramNode{
		{ID: "changed", Type: "Function", Name: "Changed", FilePath: "cache.go", StartLine: 40, EndLine: 45, Identity: "changed", Changed: true},
	}}
	got, _ := Generate(snapshot, Input{InvestigationID: "inv", RepositoryID: "repo", RevisionID: "rev", ChangedIdentities: map[string]bool{"changed": true}, FailureText: "cache package failed", EvidenceIDs: []domain.ID{"ci"}, MaxCandidates: 10})
	if len(got) != 0 {
		t.Fatalf("unconnected changed symbol became candidate: %#v", got)
	}
}

func TestScoreEvidenceStaysInItsDimension(t *testing.T) {
	changed := domain.ProgramNode{ID: "changed", Type: "Function", Name: "Changed", FilePath: "cache.go", StartLine: 10, EndLine: 20, Identity: "changed", Changed: true}
	utility := domain.ProgramNode{ID: "utility", Type: "Function", Name: "Utility", FilePath: "cache.go", StartLine: 30, EndLine: 40, Identity: "utility"}
	snapshot := programrepo.Snapshot{RepositoryID: "repo", RevisionID: "rev", Nodes: []domain.ProgramNode{changed, utility}, Relationships: []domain.Relationship{{ID: "call", SourceID: "changed", TargetID: "utility", Type: "CALLS"}}}
	got, _ := Generate(snapshot, Input{InvestigationID: "inv", RepositoryID: "repo", RevisionID: "rev", StackFrames: []Frame{{File: "cache.go", Line: 12, EvidenceIDs: []domain.ID{"frame"}}}, EvidenceIDs: []domain.ID{"ci"}, ChangeEvidenceIDs: []domain.ID{"diff"}, ChangedIdentities: map[string]bool{"changed": true}, MaxCandidates: 10})
	var direct, expanded *domain.CandidateLocation
	for i := range got {
		if got[i].Location.SymbolIdentity == changed.Identity {
			direct = &got[i]
		}
		if got[i].Location.SymbolIdentity == utility.Identity {
			expanded = &got[i]
		}
	}
	if direct == nil || direct.Score.ChangeRelevance == 0 {
		t.Fatalf("changed evidence did not reach direct candidate: %#v", got)
	}
	if gotIDs := direct.Score.EvidenceByDimension["change"]; len(gotIDs) != 1 || gotIDs[0] != "diff" {
		t.Fatalf("change evidence reused unrelated IDs: %#v", direct.Score.EvidenceByDimension)
	}
	if direct.Score.EvidenceByDimension["execution"][0] != "frame" {
		t.Fatalf("execution evidence was not frame-scoped: %#v", direct.Score.EvidenceByDimension)
	}
	if expanded != nil && expanded.Score.EvidenceByDimension["dependency"][0] == "ci" {
		t.Fatalf("dependency evidence reused CI evidence: %#v", expanded.Score.EvidenceByDimension)
	}
}

func TestSignalsRequireDimensionSpecificEvidence(t *testing.T) {
	score := evaluateSignals(CandidateContext{
		Execution:          true,
		Changed:            true,
		Expanded:           true,
		Behavioural:        true,
		Evidence:           []domain.ID{"ci-stack"},
		ChangeEvidence:     nil,
		DependencyEvidence: nil,
	})
	if score.ExecutionRelevance == 0 || score.EvidenceByDimension["execution"][0] != "ci-stack" {
		t.Fatalf("execution evidence missing: %#v", score)
	}
	if score.ChangeRelevance != 0 || score.DependencyRelevance != 0 || contains(score.AvailableDimensions, "change") || contains(score.AvailableDimensions, "dependency") {
		t.Fatalf("unrelated CI evidence increased change/dependency relevance: %#v", score)
	}
}
