package investigation

import (
	"context"
	"testing"

	"github.com/causent/malenia/internal/domain"
)

type testAction struct{ kind string }

func (a testAction) Type() string { return a.kind }
func (a testAction) Definition() ActionDefinition {
	return ActionDefinition{ID: a.kind, Type: a.kind, Description: "test", Timeout: 1}
}

type capabilityAction struct {
	kind string
	caps []EvidenceCapability
}

func (a capabilityAction) Type() string { return a.kind }
func (a capabilityAction) Definition() ActionDefinition {
	return ActionDefinition{ID: a.kind, Type: a.kind, Description: "test", Timeout: 1, Capabilities: a.caps}
}
func (a capabilityAction) Execute(context.Context, ActionInput) (ActionOutput, error) {
	return ActionOutput{}, nil
}
func (a testAction) Execute(context.Context, ActionInput) (ActionOutput, error) {
	return ActionOutput{}, nil
}

func TestSelectChoosesInspectableActionAndStopsOnBudget(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(testAction{kind: "EvaluateHypothesis"}); err != nil {
		t.Fatal(err)
	}
	decision := Select(State{Hypotheses: []domain.Hypothesis{{ID: "h", Status: domain.HypInconclusive}}, Budget: domain.InvestigationBudget{MaxIterations: 1}}, r, DefaultScorePolicy)
	if decision.Selected.ActionType != "EvaluateHypothesis" || decision.Selected.Reason == "" {
		t.Fatalf("decision=%#v", decision)
	}
	decision = Select(State{Hypotheses: []domain.Hypothesis{{ID: "h", Status: domain.HypInconclusive}}, Budget: domain.InvestigationBudget{MaxIterations: 1, IterationsUsed: 1}}, r, DefaultScorePolicy)
	if decision.StoppingReason == "" {
		t.Fatal("expected budget stop")
	}
}

func TestSelectChangesWithObjectiveEvidence(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(testAction{kind: "InspectSynchronization"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(testAction{kind: "TraceVariable"}); err != nil {
		t.Fatal(err)
	}
	state := State{
		Objectives: []domain.AdaptiveObjective{{ID: "memory", Status: "unresolved", Predicate: "same object", RequiredEvidence: []string{"source identity"}, CandidateActions: []string{"TraceVariable"}, Target: "cacher.go:496:Read", TargetSymbol: "go:cacher.Read"}},
		Budget:     domain.InvestigationBudget{MaxIterations: 2},
	}
	first := Select(state, r, DefaultScorePolicy)
	if first.Selected.ActionType != "TraceVariable" {
		t.Fatalf("selected %s, want TraceVariable: %#v", first.Selected.ActionType, first)
	}
	if first.Selected.ObjectiveID != "memory" {
		t.Fatalf("selected action did not retain dependency identity: %#v", first)
	}
	if first.Selected.Input.InvestigationID != "" || len(first.Selected.Input.References) != 1 || first.Selected.Input.References[0] != "cacher.go:496:Read" || first.Selected.Input.Metadata["target_symbol"] != "go:cacher.Read" || first.Selected.Input.Metadata["predicate"] != "same object" || first.Selected.Input.Metadata["required_evidence"] != "source identity" {
		t.Fatalf("selected objective evidence request was not bound to action input: %#v", first.Selected.Input)
	}
	state.Objectives[0].CandidateActions = []string{"InspectSynchronization"}
	second := Select(state, r, DefaultScorePolicy)
	if second.Selected.ActionType != "InspectSynchronization" {
		t.Fatalf("selected %s after evidence change, want InspectSynchronization: %#v", second.Selected.ActionType, second)
	}
}

func TestSelectDoesNotRepeatCompletedAdaptiveActionWithTarget(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(testAction{kind: "InspectSynchronization"}); err != nil {
		t.Fatal(err)
	}
	state := State{
		Objectives: []domain.AdaptiveObjective{{ID: "ordering", Status: "unresolved", CandidateActions: []string{"InspectSynchronization"}, Target: "cacher.go:1389:Cacher.Stop", TargetSymbol: "go:cacher.Cacher.Stop"}},
		Activities: []domain.Activity{{ID: "activity:inv:adaptive:1", Type: "InspectSynchronization", ObjectiveID: "ordering", Status: domain.ActivityCompleted, InputRefs: []string{"cacher.go:1389:Cacher.Stop"}}},
		Budget:     domain.InvestigationBudget{MaxIterations: 2},
	}
	decision := Select(state, r, DefaultScorePolicy)
	if decision.StoppingReason == "" || decision.Selected.ActionType != "" {
		t.Fatalf("completed targeted adaptive action was selected again: %#v", decision)
	}
}

func TestSelectAllowsSameActionForDifferentTarget(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(testAction{kind: "InspectSynchronization"}); err != nil {
		t.Fatal(err)
	}
	state := State{
		Objectives: []domain.AdaptiveObjective{{ID: "ordering", Status: "unresolved", CandidateActions: []string{"InspectSynchronization"}, Target: "cacher.go:1389:Stop"}},
		Activities: []domain.Activity{{ID: "activity:inv:adaptive:1", Type: "InspectSynchronization", Status: domain.ActivityCompleted, InputRefs: []string{"cacher.go:496:Read"}}},
		Budget:     domain.InvestigationBudget{MaxIterations: 2},
	}
	decision := Select(state, r, DefaultScorePolicy)
	if decision.StoppingReason != "" || decision.Selected.Input.References[0] != "cacher.go:1389:Stop" {
		t.Fatalf("different target was incorrectly treated as completed: %#v", decision)
	}
}

func TestSelectReportsBudgetExhaustionAfterCompletedAdaptiveWork(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(testAction{kind: "InspectSynchronization"}); err != nil {
		t.Fatal(err)
	}
	decision := Select(State{
		Objectives: []domain.AdaptiveObjective{{ID: "ordering", Status: "unresolved", CandidateActions: []string{"InspectSynchronization"}}},
		Budget:     domain.InvestigationBudget{MaxIterations: 4, IterationsUsed: 4},
	}, r, DefaultScorePolicy)
	if decision.StoppingReason != "iteration budget exhausted" {
		t.Fatalf("unexpected budget decision: %#v", decision)
	}
}

func TestSelectPrefersRequirementCapableAction(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(testAction{kind: "GenericHighRelevance"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(capabilityAction{kind: "InspectFunction", caps: []EvidenceCapability{{ClaimKind: "source function", MinimumBasis: "SourceVerified", SubjectScope: "target_declaration"}}}); err != nil {
		t.Fatal(err)
	}
	state := State{Hypotheses: []domain.Hypothesis{{Status: domain.HypInconclusive}}, Objectives: []domain.AdaptiveObjective{{ID: "memory", Status: "unresolved", CandidateActions: []string{"GenericHighRelevance", "InspectFunction"}, Requirements: []domain.EvidenceRequirement{{ClaimKind: "source function", MinimumBasis: "SourceVerified"}}, MissingRequirements: []string{"source function"}, Target: "f.go:1", TargetSymbol: "go:f"}}, Budget: domain.InvestigationBudget{MaxIterations: 1}}
	decision := Select(state, r, DefaultScorePolicy)
	if decision.Selected.ActionType != "InspectFunction" {
		t.Fatalf("selected incapable action: %#v", decision)
	}
}

func TestSelectReportsUnsupportedAndUnavailableTypedActions(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(capabilityAction{kind: "InspectCleanup", caps: []EvidenceCapability{{ClaimKind: "source cleanup", MinimumBasis: "SourceVerified", SubjectScope: "target_declaration"}}}); err != nil {
		t.Fatal(err)
	}
	unsupported := Select(State{Objectives: []domain.AdaptiveObjective{{ID: "ordering", Status: "unresolved", CandidateActions: []string{"InspectCleanup"}, Requirements: []domain.EvidenceRequirement{{ClaimKind: "synchronization-ordering", MinimumBasis: "SourceVerified", Ordering: "happens-before"}}, MissingRequirements: []string{"synchronization-ordering (happens-before)"}, Target: "f.go:1", TargetSymbol: "go:f"}}, Budget: domain.InvestigationBudget{MaxIterations: 1}}, r, DefaultScorePolicy)
	if unsupported.StoppingReason == "" || len(unsupported.Dispositions) != 1 || unsupported.Dispositions[0].Status != "unsupported" {
		t.Fatalf("unsupported action was not classified: %#v", unsupported)
	}
	available := Select(State{Objectives: []domain.AdaptiveObjective{{ID: "ordering", Status: "unresolved", CandidateActions: []string{"InspectCleanup"}, Requirements: []domain.EvidenceRequirement{{ClaimKind: "source cleanup", MinimumBasis: "SourceVerified"}}, MissingRequirements: []string{"source cleanup"}}}, Budget: domain.InvestigationBudget{MaxIterations: 1}}, r, DefaultScorePolicy)
	if available.StoppingReason == "" || len(available.Dispositions) != 1 || available.Dispositions[0].Status != "blocked/unavailable" {
		t.Fatalf("unavailable action was not classified: %#v", available)
	}
}

func TestRun64TypedObjectivesDoNotSpendAdaptiveSlotOnIncapableActions(t *testing.T) {
	r := NewRegistry()
	for _, kind := range []string{"InspectFunction", "FindReferences", "InspectCleanup", "InspectSynchronization", "TraceCallers", "TraceCallees"} {
		if err := r.Register(capabilityAction{kind: kind, caps: map[string][]EvidenceCapability{
			"InspectFunction":        {{ClaimKind: "source function", MinimumBasis: "SourceVerified", SubjectScope: "target_declaration"}},
			"FindReferences":         {{ClaimKind: "source references", MinimumBasis: "SourceVerified", SubjectScope: "target_declaration"}},
			"InspectCleanup":         {{ClaimKind: "source cleanup", MinimumBasis: "SourceVerified", SubjectScope: "target_declaration"}},
			"InspectSynchronization": {{ClaimKind: "source synchronization", MinimumBasis: "SourceVerified", SubjectScope: "target_declaration"}},
		}[kind]}); err != nil {
			t.Fatal(err)
		}
	}
	objectives := []domain.AdaptiveObjective{
		{ID: "exact-memory", Status: "unresolved", CandidateActions: []string{"InspectFunction", "FindReferences"}, Requirements: []domain.EvidenceRequirement{{ClaimKind: "same-runtime-instance", MinimumBasis: "RuntimeObserved", SameInstance: true}}, MissingRequirements: []string{"same-runtime-instance"}, Target: "cacher.go:496", TargetSymbol: "go:cacher.New"},
		{ID: "shutdown-ordering", Status: "unresolved", CandidateActions: []string{"InspectCleanup", "InspectSynchronization"}, Requirements: []domain.EvidenceRequirement{{ClaimKind: "synchronization-ordering", MinimumBasis: "SourceVerified", Ordering: "happens-before"}}, MissingRequirements: []string{"synchronization-ordering (happens-before)"}, Target: "cacher.go:1389", TargetSymbol: "go:cacher.Cacher.Stop"},
		{ID: "happens-before", Status: "unresolved", CandidateActions: []string{"InspectSynchronization", "TraceCallers", "TraceCallees"}, Requirements: []domain.EvidenceRequirement{{ClaimKind: "synchronization-ordering", MinimumBasis: "SourceVerified", Ordering: "happens-before"}}, MissingRequirements: []string{"synchronization-ordering (happens-before)"}, Target: "cacher.go:1389", TargetSymbol: "go:cacher.Cacher.Stop"},
	}
	decision := Select(State{Objectives: objectives, Budget: domain.InvestigationBudget{MaxIterations: 4, MaxActivities: 4}}, r, DefaultScorePolicy)
	if decision.Selected.ActionType != "" || decision.StoppingReason != "no capable action remains" {
		t.Fatalf("incapable action consumed run-64 slot: %#v", decision)
	}
	if len(decision.Dispositions) == 0 {
		t.Fatal("missing unsupported dispositions")
	}
	for _, disposition := range decision.Dispositions {
		if disposition.Status != "unsupported" {
			t.Fatalf("unexpected disposition: %#v", disposition)
		}
	}
}
