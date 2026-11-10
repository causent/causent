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
		Objectives: []domain.AdaptiveObjective{{ID: "memory", Status: "unresolved", CandidateActions: []string{"TraceVariable"}}},
		Budget:     domain.InvestigationBudget{MaxIterations: 2},
	}
	first := Select(state, r, DefaultScorePolicy)
	if first.Selected.ActionType != "TraceVariable" {
		t.Fatalf("selected %s, want TraceVariable: %#v", first.Selected.ActionType, first)
	}
	state.Objectives[0].CandidateActions = []string{"InspectSynchronization"}
	second := Select(state, r, DefaultScorePolicy)
	if second.Selected.ActionType != "InspectSynchronization" {
		t.Fatalf("selected %s after evidence change, want InspectSynchronization: %#v", second.Selected.ActionType, second)
	}
}
