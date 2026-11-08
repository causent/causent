package relationships

import (
	"github.com/causent/causent/internal/domain"
	"testing"
)

func TestDiscoverSeparatesSharedAndIndependentFailures(t *testing.T) {
	failures := []domain.FailureEpisode{{ID: "f1"}, {ID: "f2"}, {ID: "f3"}}
	candidates := []domain.CandidateLocation{{ID: "c1", SupportingEvidenceIDs: []domain.ID{"e1"}}, {ID: "c2", SupportingEvidenceIDs: []domain.ID{"e2"}}}
	rels := []domain.Relationship{{ID: "a", SourceType: "failure_episode", SourceID: "f1", TargetType: "candidate_location", TargetID: "c1", Type: "ASSOCIATED_WITH", EvidenceIDs: []domain.ID{"e1"}}, {ID: "b", SourceType: "failure_episode", SourceID: "f2", TargetType: "candidate_location", TargetID: "c1", Type: "ASSOCIATED_WITH", EvidenceIDs: []domain.ID{"e1"}}, {ID: "c", SourceType: "failure_episode", SourceID: "f3", TargetType: "candidate_location", TargetID: "c2", Type: "ASSOCIATED_WITH", EvidenceIDs: []domain.ID{"e2"}}}
	result := Discover("inv", failures, candidates, rels)
	if len(result.Groups) != 2 {
		t.Fatalf("groups=%d", len(result.Groups))
	}
	foundRelated, foundIndependent := false, false
	for _, g := range result.Groups {
		if g.Status == "potentially_related" {
			foundRelated = true
		}
		if g.Status == "independent" {
			foundIndependent = true
		}
	}
	if !foundRelated || !foundIndependent {
		t.Fatalf("groups=%#v", result.Groups)
	}
	for _, r := range result.Relationships {
		if r.Type == "POTENTIALLY_RELATED" && r.Metadata["causal_claim"] != "false" {
			t.Fatal("shared candidate became causal claim")
		}
	}
}
