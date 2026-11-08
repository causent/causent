package persistence

import (
	"github.com/causent/causent/internal/domain"
	"testing"
	"time"
)

func TestArchitectureRecordsAndTypedRelationshipsRoundTrip(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()
	repo := domain.Repository{ID: "repo-1", Provider: "github", Owner: "causent", Name: "causent", CanonicalID: "github:causent/causent"}
	if err := store.SaveRepository(repo); err != nil {
		t.Fatal(err)
	}
	var loaded domain.Repository
	if err := store.GetArchitecture("repository", repo.ID, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.CanonicalID != repo.CanonicalID {
		t.Fatalf("canonical id = %q", loaded.CanonicalID)
	}
	rel := domain.Relationship{ID: "rel-1", InvestigationID: "inv-1", SourceType: "failure_episode", SourceID: "failure-1", TargetType: "candidate_location", TargetID: "candidate-1", Type: "MANIFESTED_AT", EvidenceIDs: []domain.ID{"ev-1"}, CreatedAt: time.Now().UTC()}
	if err := store.SaveRelationship(rel); err != nil {
		t.Fatal(err)
	}
	rels, err := store.ListRelationships("inv-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 1 || rels[0].Type != "MANIFESTED_AT" {
		t.Fatalf("relationships = %#v", rels)
	}
}

func TestHypothesisDetailsRoundTripAndVersioning(t *testing.T) {
	store := openTestStore(t)
	defer store.Close()
	now := time.Now().UTC()
	h := domain.Hypothesis{ID: "h1", InvestigationID: "inv", HypothesisGroupID: "g1", Version: 2, SupersedesHypothesisID: "h0", Statement: "possible explanation", RelatedFailureIDs: []string{"f1", "f2"}, CandidateLocationIDs: []string{"c1"}, SupportingEvidenceIDs: []domain.ID{"e1"}, Relevance: .7, Status: domain.HypUnderInvestigation, CreatedAt: now, UpdatedAt: now}
	if err := store.SaveInvestigation(domain.Investigation{ID: "inv", RepoPath: "/tmp", Status: domain.StatusCreated, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveHypothesis(h); err != nil {
		t.Fatal(err)
	}
	got, err := store.ListHypotheses("inv")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("hypotheses=%d", len(got))
	}
	if got[0].Version != 2 || got[0].HypothesisGroupID != "g1" || len(got[0].RelatedFailureIDs) != 2 || got[0].Relevance != .7 {
		t.Fatalf("round trip=%#v", got[0])
	}
}
