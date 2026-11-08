// Package history retrieves revision-aware context from previous investigations.
// It deliberately produces historical associations, not causal conclusions.
package history

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/causent/causent/internal/domain"
	"github.com/causent/causent/internal/persistence"
)

type Input struct {
	InvestigationID domain.ID
	RepositoryID    string
	RevisionID      string
	Failures        []domain.FailureEpisode
	Candidates      []domain.CandidateLocation
	EvidenceIDs     []domain.ID
}

type Result struct {
	References    []domain.HistoricalReference
	Relationships []domain.Relationship
	Evidence      []domain.Evidence
}

// Discover compares current observations against persisted observations from
// the same repository. Matching a message, path, or symbol is only a retrieval
// signal; every output carries explicit revision uncertainty.
func Discover(store *persistence.Store, in Input) (Result, error) {
	if store == nil {
		return Result{}, fmt.Errorf("store is required")
	}
	var executions []domain.CIExecution
	if err := store.ListArchitecture("ci_execution", "", func(data []byte) error {
		var value domain.CIExecution
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		executions = append(executions, value)
		return nil
	}); err != nil {
		return Result{}, err
	}
	repoByExecution := map[string]string{}
	for _, execution := range executions {
		repoByExecution[execution.ID] = execution.RepositoryID
	}
	var failures []domain.FailureEpisode
	if err := store.ListArchitecture("failure_episode", "", func(data []byte) error {
		var value domain.FailureEpisode
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		failures = append(failures, value)
		return nil
	}); err != nil {
		return Result{}, err
	}
	var historicalCandidates []domain.CandidateLocation
	if err := store.ListArchitecture("candidate", "", func(data []byte) error {
		var value domain.CandidateLocation
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		historicalCandidates = append(historicalCandidates, value)
		return nil
	}); err != nil {
		return Result{}, err
	}
	currentIDs := map[string]bool{}
	for _, failure := range in.Failures {
		currentIDs[failure.ID] = true
	}
	var result Result
	for _, current := range in.Failures {
		for _, previous := range failures {
			if currentIDs[previous.ID] || repoByExecution[previous.ExecutionID] != in.RepositoryID {
				continue
			}
			similarity := messageSimilarity(current.FailureMessage, previous.FailureMessage)
			if similarity < .65 {
				continue
			}
			previousInvestigation := domain.ID("historical:" + previous.ExecutionID)
			for _, execution := range executions {
				if execution.ID == previous.ExecutionID && execution.ExternalExecutionID != "" {
					previousInvestigation = domain.ID(execution.ExternalExecutionID)
				}
			}
			payload := fmt.Sprintf("previous_investigation=%s\nprevious_failure=%s\nprevious_execution=%s\nmessage_similarity=%.3f\ncurrent_revision=%s\nprevious_revision=unresolved", previousInvestigation, previous.ID, previous.ExecutionID, similarity, in.RevisionID)
			evidence := historicalEvidence(in.InvestigationID, payload, current.ID, previous.ID)
			relationship := domain.Relationship{ID: "historical:failure:" + current.ID + ":" + previous.ID, InvestigationID: in.InvestigationID, SourceType: "failure_episode", SourceID: current.ID, TargetType: "historical_failure_episode", TargetID: previous.ID, Type: "HISTORICAL_RELATED", RevisionID: in.RevisionID, EvidenceIDs: []domain.ID{evidence.ID}, Metadata: map[string]string{"causal_claim": "false", "revision_match": "uncertain", "similarity": fmt.Sprintf("%.3f", similarity)}, CreatedAt: time.Now().UTC()}
			result.Evidence = append(result.Evidence, evidence)
			result.Relationships = append(result.Relationships, relationship)
			result.References = append(result.References, domain.HistoricalReference{InvestigationID: previousInvestigation, FailureID: previous.ID, Similarity: similarity, RelationshipID: relationship.ID, EvidenceID: evidence.ID, RevisionID: in.RevisionID, Uncertainty: "historical similarity does not establish identical code or cause"})
		}
	}
	for _, current := range in.Candidates {
		for _, previous := range historicalCandidates {
			if previous.InvestigationID == in.InvestigationID || previous.Location.RepositoryID != in.RepositoryID || current.Location.SymbolIdentity == "" || current.Location.SymbolIdentity != previous.Location.SymbolIdentity {
				continue
			}
			result.Relationships = append(result.Relationships, domain.Relationship{ID: "historical:candidate:" + current.ID + ":" + previous.ID, InvestigationID: in.InvestigationID, SourceType: "candidate_location", SourceID: current.ID, TargetType: "historical_candidate_location", TargetID: previous.ID, Type: "HISTORICAL_CANDIDATE_ASSOCIATION", RevisionID: in.RevisionID, EvidenceIDs: append([]domain.ID{}, in.EvidenceIDs...), Metadata: map[string]string{"causal_claim": "false", "symbol_identity_match": "true", "revision_match": "uncertain"}, CreatedAt: time.Now().UTC()})
			if len(result.Relationships) >= 200 {
				break
			}
		}
	}
	sort.SliceStable(result.References, func(i, j int) bool { return result.References[i].Similarity > result.References[j].Similarity })
	return result, nil
}

func historicalEvidence(inv domain.ID, payload string, current, previous string) domain.Evidence {
	sum := sha256.Sum256([]byte(string(inv) + current + previous + payload))
	return domain.Evidence{ID: domain.ID("evidence:historical:" + hex.EncodeToString(sum[:8])), InvestigationID: inv, Type: domain.EvidenceHistorical, Source: "cross-investigation-history", Timestamp: time.Now().UTC(), ContentRef: "historical-failure-context", Payload: payload, Digest: hex.EncodeToString(sum[:]), Provenance: "deterministic cross-investigation retrieval; revision match uncertain"}
}

var nonWord = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func messageSimilarity(a, b string) float64 {
	at, bt := tokens(a), tokens(b)
	if len(at) == 0 || len(bt) == 0 {
		return 0
	}
	intersection := 0
	for token := range at {
		if bt[token] {
			intersection++
		}
	}
	return float64(intersection) / math.Max(float64(len(at)), float64(len(bt)))
}

func tokens(value string) map[string]bool {
	out := map[string]bool{}
	for _, token := range strings.Fields(strings.ToLower(nonWord.ReplaceAllString(value, " "))) {
		if len(token) > 2 {
			out[token] = true
		}
	}
	return out
}
