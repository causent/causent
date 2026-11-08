package investigation

import (
	"context"
	"fmt"
	"github.com/causent/malenia/internal/domain"
	"sort"
	"time"
)

type State struct {
	InvestigationID domain.ID
	Hypotheses      []domain.Hypothesis
	Questions       []domain.InvestigationQuestion
	Activities      []domain.Activity
	Experiments     []domain.Experiment
	Budget          domain.InvestigationBudget
}
type ActionScore struct {
	DiagnosticRelevance  float64
	UncertaintyReduction float64
	Discrimination       float64
	EvidenceQuality      float64
	ExecutionCost        float64
	ExecutionRisk        float64
	ExpectedLatency      float64
	Total                float64
}
type ActionCandidate struct {
	ActionType string
	Input      ActionInput
	Score      ActionScore
	Reason     string
}
type Decision struct {
	Selected       ActionCandidate
	Considered     []ActionCandidate
	StoppingReason string
}
type ScorePolicy struct{ Relevance, Uncertainty, Discrimination, Quality, Cost, Risk, Latency float64 }

var DefaultScorePolicy = ScorePolicy{Relevance: 4, Uncertainty: 5, Discrimination: 6, Quality: 2, Cost: 2, Risk: 3, Latency: 1}

func Select(state State, registry *Registry, policy ScorePolicy) Decision {
	if state.Budget.MaxIterations > 0 && state.Budget.IterationsUsed >= state.Budget.MaxIterations {
		return Decision{StoppingReason: "iteration budget exhausted"}
	}
	if state.Budget.MaxActivities > 0 && state.Budget.ActivitiesUsed >= state.Budget.MaxActivities {
		return Decision{StoppingReason: "activity budget exhausted"}
	}
	if state.Budget.MaxExperiments > 0 && state.Budget.ExperimentsUsed >= state.Budget.MaxExperiments {
		return Decision{StoppingReason: "experiment budget exhausted"}
	}
	var considered []ActionCandidate
	for _, definition := range registry.Definitions() {
		if definition.Type == "" || completed(state, definition.Type) {
			continue
		}
		unresolved := 0
		for _, h := range state.Hypotheses {
			if h.Status == domain.HypProposed || h.Status == domain.HypUnderInvestigation || h.Status == domain.HypInconclusive || h.Status == domain.HypWeakened {
				unresolved++
			}
		}
		if unresolved == 0 {
			continue
		}
		score := ActionScore{DiagnosticRelevance: float64(unresolved), UncertaintyReduction: 1, Discrimination: .5, EvidenceQuality: 1, ExecutionCost: 1, ExecutionRisk: 1, ExpectedLatency: 1}
		switch definition.Type {
		case "CompareBaseAndHead", "CompareRevisions":
			score.Discrimination = 1
			score.UncertaintyReduction = 1.5
		case "RunTargetedTest", "RerunFailingTest":
			score.Discrimination = .9
			score.UncertaintyReduction = 1.25
		case "EvaluateHypothesis":
			score.Discrimination = 1
			score.UncertaintyReduction = 1.2
		}
		score.Total = score.DiagnosticRelevance*policy.Relevance + score.UncertaintyReduction*policy.Uncertainty + score.Discrimination*policy.Discrimination + score.EvidenceQuality*policy.Quality - score.ExecutionCost*policy.Cost - score.ExecutionRisk*policy.Risk - score.ExpectedLatency*policy.Latency
		considered = append(considered, ActionCandidate{ActionType: definition.Type, Score: score, Reason: fmt.Sprintf("%d unresolved hypothesis(es); expected uncertainty reduction %.2f at cost %.2f", unresolved, score.UncertaintyReduction, score.ExecutionCost)})
	}
	if len(considered) == 0 {
		return Decision{StoppingReason: "no useful uncompleted actions remain"}
	}
	sort.SliceStable(considered, func(i, j int) bool { return considered[i].Score.Total > considered[j].Score.Total })
	return Decision{Selected: considered[0], Considered: considered}
}
func completed(state State, kind string) bool {
	for _, a := range state.Activities {
		if a.Type == kind && a.Status == domain.ActivityCompleted {
			return true
		}
	}
	return false
}
func Execute(ctx context.Context, state State, registry *Registry, decision Decision) (ActionOutput, error) {
	if decision.StoppingReason != "" {
		return ActionOutput{}, fmt.Errorf("investigation stopped: %s", decision.StoppingReason)
	}
	a, ok := registry.Get(decision.Selected.ActionType)
	if !ok {
		return ActionOutput{}, fmt.Errorf("action %q is not registered", decision.Selected.ActionType)
	}
	return a.Execute(ctx, decision.Selected.Input)
}
func TimedOut(start time.Time, budget domain.InvestigationBudget) bool {
	return budget.MaxDuration > 0 && time.Since(start) >= budget.MaxDuration
}
