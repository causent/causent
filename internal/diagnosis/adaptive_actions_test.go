package diagnosis

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/investigation"
	programrepo "github.com/causent/malenia/internal/repository"
)

type adaptiveRepositoryPayload struct {
	Action, Target, Outcome, Progress string
	Nodes                             []domain.ProgramNode
	Relationships                     []domain.Relationship
}

func executeRepositoryActionFixture(t *testing.T, target, kind string, snapshot programrepo.Snapshot) investigation.ActionOutput {
	t.Helper()
	dir := newRepo(t)
	commit(t, dir, "adaptive action fixture", map[string]string{"source.go": "package source\n"})
	d := &Diagnoser{cfg: Config{RepoPath: dir}, snapshot: &snapshot}
	action := repositoryAction{diagnoser: d, workspace: dir, kind: kind, target: target}
	out, err := action.Execute(context.Background(), investigation.ActionInput{InvestigationID: "inv-adaptive"})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func decodeAdaptiveRepositoryEvidence(t *testing.T, out investigation.ActionOutput) adaptiveRepositoryPayload {
	t.Helper()
	if len(out.Evidence) != 1 {
		t.Fatalf("expected one durable evidence item: %#v", out)
	}
	var payload adaptiveRepositoryPayload
	if err := json.Unmarshal([]byte(out.Evidence[0].Payload), &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestRepositoryActionResolvesNodeAndRelationshipsByNodeID(t *testing.T) {
	node := domain.ProgramNode{ID: "pn-stop", Identity: "go:pkg/file.go:Method:Cacher.Stop", FilePath: "file.go"}
	other := domain.ProgramNode{ID: "pn-other", Identity: "go:other/file.go:Method:Cacher.Stop", FilePath: "other.go"}
	snapshot := programrepo.Snapshot{Nodes: []domain.ProgramNode{node, other}, Relationships: []domain.Relationship{
		{ID: "rel-call", SourceID: node.ID, TargetID: "pn-wait", Type: "CALLS"},
		{ID: "rel-unrelated", SourceID: other.ID, TargetID: "pn-other-target", Type: "CALLS"},
	}}
	out := executeRepositoryActionFixture(t, node.Identity, "InspectSynchronization", snapshot)
	payload := decodeAdaptiveRepositoryEvidence(t, out)
	if len(payload.Nodes) != 1 || payload.Nodes[0].ID != node.ID {
		t.Fatalf("wrong target node selected: %#v", payload.Nodes)
	}
	if len(payload.Relationships) != 1 || payload.Relationships[0].ID != "rel-call" {
		t.Fatalf("wrong relationships returned: %#v", payload.Relationships)
	}
	if out.Metadata["outcome"] != "relationships_found" {
		t.Fatalf("unexpected relationship outcome: %#v", out.Metadata)
	}
}

func TestRepositoryActionReportsNoRelationships(t *testing.T) {
	node := domain.ProgramNode{ID: "pn-stop", Identity: "go:pkg/file.go:Method:Cacher.Stop"}
	out := executeRepositoryActionFixture(t, node.Identity, "InspectSynchronization", programrepo.Snapshot{Nodes: []domain.ProgramNode{node}})
	payload := decodeAdaptiveRepositoryEvidence(t, out)
	if len(payload.Nodes) != 1 || len(payload.Relationships) != 0 || payload.Outcome != "no_relationships" || out.Metadata["progress"] != "none" {
		t.Fatalf("missing explicit no-relationship outcome: payload=%#v metadata=%#v", payload, out.Metadata)
	}
}

func TestRepositoryActionReportsUnresolvedTarget(t *testing.T) {
	out := executeRepositoryActionFixture(t, "go:missing:Cacher.Stop", "InspectSynchronization", programrepo.Snapshot{})
	payload := decodeAdaptiveRepositoryEvidence(t, out)
	if len(payload.Nodes) != 0 || payload.Outcome != "unresolved_target" || out.Metadata["progress"] != "none" {
		t.Fatalf("missing explicit unresolved-target outcome: payload=%#v metadata=%#v", payload, out.Metadata)
	}
}

func TestRepositoryActionDoesNotUseSameNameFromAnotherIdentity(t *testing.T) {
	target := domain.ProgramNode{ID: "pn-target", Identity: "go:pkg/one.go:Method:Stop"}
	unrelated := domain.ProgramNode{ID: "pn-other", Identity: "go:pkg/two.go:Method:Stop"}
	out := executeRepositoryActionFixture(t, target.Identity, "InspectSynchronization", programrepo.Snapshot{
		Nodes:         []domain.ProgramNode{target, unrelated},
		Relationships: []domain.Relationship{{ID: "wrong", SourceID: unrelated.ID, TargetID: "pn-x", Type: "CALLS"}},
	})
	payload := decodeAdaptiveRepositoryEvidence(t, out)
	if len(payload.Relationships) != 0 || payload.Relationships != nil && payload.Relationships[0].ID == "wrong" {
		t.Fatalf("unrelated same-name relationship leaked: %#v", payload.Relationships)
	}
}

func TestRepositoryActionRepeatedEvidenceIsNotProgress(t *testing.T) {
	node := domain.ProgramNode{ID: "pn-stop", Identity: "go:pkg/file.go:Method:Cacher.Stop"}
	snapshot := programrepo.Snapshot{Nodes: []domain.ProgramNode{node}}
	first := executeRepositoryActionFixture(t, node.Identity, "InspectSynchronization", snapshot)
	second := executeRepositoryActionFixture(t, node.Identity, "InspectSynchronization", snapshot)
	if first.Metadata["progress"] != "none" || second.Metadata["progress"] != "none" {
		t.Fatalf("empty relationship results were treated as progress: first=%#v second=%#v", first.Metadata, second.Metadata)
	}
	if adaptiveProducesNewEvidence(&Report{Evidence: []EvidenceItem{{ID: string(first.Evidence[0].ID)}}}, second.Evidence) {
		t.Fatal("repeated action evidence was counted as new investigation progress")
	}
}
