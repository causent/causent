package diagnosis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/investigation"
	programrepo "github.com/causent/malenia/internal/repository"
)

// repositoryAction performs bounded, deterministic queries over a fresh
// revision-scoped repository snapshot. It returns facts extracted by the
// analyzer, never model-generated claims.
type repositoryAction struct {
	diagnoser *Diagnoser
	workspace string
	kind      string
	target    string
}

func (a repositoryAction) Type() string { return a.kind }
func (a repositoryAction) Definition() investigation.ActionDefinition {
	return investigation.ActionDefinition{
		ID: a.kind + "-v1", Type: a.kind, Description: "bounded revision-scoped repository inspection",
		InputSchema: "investigation_id,target_symbol", OutputSchema: "evidence_ids",
		Preconditions:        []string{"isolated_workspace", "repository_snapshot"},
		ResourceRequirements: map[string]string{"network": "not_required"}, ExecutionRisk: "low",
		Timeout: a.diagnoser.cfg.Timeout, RetryLimit: 1, Idempotent: true,
	}
}
func (a repositoryAction) Execute(ctx context.Context, input investigation.ActionInput) (investigation.ActionOutput, error) {
	repoID := "local:" + a.diagnoser.cfg.RepoPath
	commit := strings.TrimSpace(gitOutput(a.workspace, "rev-parse", "HEAD"))
	if commit == "" {
		commit = "unknown"
	}
	var snapshot programrepo.Snapshot
	if a.diagnoser.snapshot != nil {
		snapshot = *a.diagnoser.snapshot
	} else {
		var err error
		snapshot, err = (programrepo.Analyzer{}).Analyze(ctx, a.workspace, repoID, "adaptive:"+commit, commit)
		if err != nil {
			return investigation.ActionOutput{}, err
		}
	}
	selected := make([]domain.ProgramNode, 0, 16)
	for _, node := range snapshot.Nodes {
		if a.target == "" || node.Identity == a.target || strings.Contains(node.Identity, a.target) {
			selected = append(selected, node)
		}
		if len(selected) >= 16 {
			break
		}
	}
	if len(selected) == 0 && a.kind == "InspectSymbol" {
		return investigation.ActionOutput{}, fmt.Errorf("symbol %q was not resolved", a.target)
	}
	var rels []domain.Relationship
	for _, rel := range snapshot.Relationships {
		match := a.target == "" || strings.Contains(rel.SourceID, a.target) || strings.Contains(rel.TargetID, a.target)
		if !match {
			continue
		}
		switch a.kind {
		case "FindReferences":
			if rel.Type != "REFERENCES" {
				continue
			}
		case "ExpandCallers", "ExpandCallees":
			if rel.Type != "CALLS" {
				continue
			}
		case "InspectDependency":
			if rel.Type != "IMPORTS" && rel.Type != "DEPENDS_ON" {
				continue
			}
		case "InspectTest":
			if rel.Type != "TESTS" {
				continue
			}
		}
		rels = append(rels, rel)
		if len(rels) >= 32 {
			break
		}
	}
	payload := struct {
		Action, Target string
		Nodes          []domain.ProgramNode
		Relationships  []domain.Relationship
	}{a.kind, a.target, selected, rels}
	data, _ := json.Marshal(payload)
	hash := sha256.Sum256(data)
	e := domain.Evidence{ID: domain.ID("evidence:adaptive:" + hex.EncodeToString(hash[:8])), InvestigationID: input.InvestigationID, Type: domain.EvidenceSourceCode, Source: "adaptive:" + a.kind, Timestamp: time.Now().UTC(), ContentRef: "repository-snapshot", Digest: hex.EncodeToString(hash[:]), Payload: string(data), Provenance: "deterministic repository analyzer; revision-scoped snapshot"}
	return investigation.ActionOutput{References: []string{string(e.ID)}, Evidence: []domain.Evidence{e}, Metadata: map[string]string{"dimension": "dependency", "action": a.kind, "target": a.target}}, nil
}

type compareRevisionsAction struct {
	diagnoser  *Diagnoser
	baseline   Baseline
	headCommit string
	kind       string
}

func (a compareRevisionsAction) Type() string {
	if a.kind != "" {
		return a.kind
	}
	return "CompareBaseAndHead"
}
func (a compareRevisionsAction) Definition() investigation.ActionDefinition {
	return investigation.ActionDefinition{ID: "compare-base-head-v1", Type: a.Type(), Description: "execute the same configured command on base and head revisions", InputSchema: "investigation_id", OutputSchema: "evidence_ids", Preconditions: []string{"base_revision", "isolated_executor"}, ResourceRequirements: map[string]string{"network": "denied-by-executor-policy"}, ExecutionRisk: "medium", Timeout: a.diagnoser.cfg.Timeout, RetryLimit: 0, Idempotent: true}
}
func (a compareRevisionsAction) Execute(ctx context.Context, input investigation.ActionInput) (investigation.ActionOutput, error) {
	comparison, err := a.diagnoser.compare(ctx, a.diagnoser.cfg.BaseRef, a.baseline, a.headCommit)
	if err != nil {
		return investigation.ActionOutput{}, err
	}
	data, _ := json.Marshal(comparison)
	hash := sha256.Sum256(data)
	e := domain.Evidence{ID: domain.ID("evidence:adaptive:" + hex.EncodeToString(hash[:8])), InvestigationID: input.InvestigationID, Type: domain.EvidenceBaselineCompare, Source: "adaptive:CompareBaseAndHead", Timestamp: time.Now().UTC(), ContentRef: "base-head-comparison", Digest: hex.EncodeToString(hash[:]), Payload: string(data), Provenance: "controlled base/head execution; same configured command; isolated worktrees"}
	outcome := "inconclusive"
	if comparison.Verdict == ClassRealRegression {
		outcome = "supports"
	}
	if comparison.Verdict == ClassPreExisting || comparison.Verdict == ClassNotReproduced {
		outcome = "contradicts"
	}
	return investigation.ActionOutput{References: []string{string(e.ID)}, Evidence: []domain.Evidence{e}, Metadata: map[string]string{"outcome": outcome, "dimension": "runtime"}}, nil
}

var _ investigation.Action = repositoryAction{}
var _ investigation.Action = compareRevisionsAction{}
