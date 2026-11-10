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
