package localization

import (
	"github.com/causent/causent/internal/domain"
	"testing"
)

func TestRankPreservesUnavailableDimensions(t *testing.T) {
	a := domain.CandidateLocation{ID: "a", Score: domain.ScoreVector{ExecutionRelevance: 1, AvailableDimensions: []string{"execution"}}}
	b := domain.CandidateLocation{ID: "b", Score: domain.ScoreVector{ChangeRelevance: 0.5, AvailableDimensions: []string{"change"}}}
	got := Rank([]domain.CandidateLocation{b, a}, DefaultWeights)
	if got[0].ID != "a" {
		t.Fatalf("top candidate = %s, want a", got[0].ID)
	}
	if Aggregate(a.Score, DefaultWeights) != 1 {
		t.Fatalf("unavailable dimensions changed normalized score")
	}
}

func TestValidateFindingRejectsMissingEvidence(t *testing.T) {
	f := domain.DiagnosticFinding{ID: "f", Statement: "possible cause", EvidenceIDs: []domain.ID{"missing"}}
	v := ValidateFinding(f, map[domain.ID]domain.Evidence{}, map[domain.ID]domain.Hypothesis{})
	if v.Valid {
		t.Fatal("finding with missing evidence was accepted")
	}
}
