package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/persistence"
)

func TestDiscoverReturnsRevisionUncertainHistoricalContext(t *testing.T) {
	store, err := persistence.Open(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	if err := store.SaveRepository(domain.Repository{ID: "repo", CanonicalID: "github:owner/repo"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCIExecution(domain.CIExecution{ID: "execution:old", RepositoryID: "repo", ExternalExecutionID: "old-investigation", HeadRevisionID: "revision:old", Status: "failed", StartedAt: &now, CompletedAt: &now}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveFailureEpisode(domain.FailureEpisode{ID: "failure:old", ExecutionID: "execution:old", FailureMessage: "timeout while reading cache", Status: "observed"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveCandidate(domain.CandidateLocation{ID: "candidate:old", InvestigationID: "old-investigation", Location: domain.CodeLocation{RepositoryID: "repo", RevisionID: "revision:old", SymbolIdentity: "go:cache:Function:Read"}}); err != nil {
		t.Fatal(err)
	}
	result, err := Discover(store, Input{InvestigationID: "new-investigation", RepositoryID: "repo", RevisionID: "revision:new", Failures: []domain.FailureEpisode{{ID: "failure:new", ExecutionID: "execution:new", FailureMessage: "timeout while reading cache", Status: "observed"}}, Candidates: []domain.CandidateLocation{{ID: "candidate:new", InvestigationID: "new-investigation", Location: domain.CodeLocation{RepositoryID: "repo", RevisionID: "revision:new", SymbolIdentity: "go:cache:Function:Read"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.References) != 1 || len(result.Evidence) != 1 || len(result.Relationships) < 2 {
		t.Fatalf("unexpected historical result: %#v", result)
	}
	if result.References[0].InvestigationID != "old-investigation" || result.Relationships[0].Metadata["causal_claim"] != "false" {
		t.Fatalf("historical provenance lost: %#v", result)
	}
	if result.Evidence[0].Type != domain.EvidenceHistorical {
		t.Fatalf("evidence type=%s", result.Evidence[0].Type)
	}
}
