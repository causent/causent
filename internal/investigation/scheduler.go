package investigation

import (
	"context"
	"fmt"
	"github.com/causent/malenia/internal/domain"
	"sort"
	"strings"
	"time"
)

type State struct {
	InvestigationID domain.ID
	Hypotheses      []domain.Hypothesis
	Objectives      []domain.AdaptiveObjective
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
	ActionType  string
	ObjectiveID string
	Input       ActionInput
	Score       ActionScore
	Reason      string
	Disposition string
}
type Decision struct {
	Selected       ActionCandidate
	Considered     []ActionCandidate
	StoppingReason string
	Dispositions   []CandidateDisposition
}
type CandidateDisposition struct {
	ActionType  string
	ObjectiveID string
	Status      string
	Reason      string
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
	var dispositions []CandidateDisposition
	for _, definition := range registry.Definitions() {
		if definition.Type == "" {
			continue
		}
		unresolved := 0
		for _, h := range state.Hypotheses {
			if h.Status == domain.HypProposed || h.Status == domain.HypUnderInvestigation || h.Status == domain.HypInconclusive || h.Status == domain.HypWeakened {
				unresolved++
			}
		}
		objectiveMatch := 0
		capabilityMatch := 0
		typedCandidateSeen := false
		var selectedObjective *domain.AdaptiveObjective
		for _, objective := range state.Objectives {
			if objective.Status == "resolved" || objective.Status == "rejected" || objective.Status == "not_applicable" {
				continue
			}
			unresolved++
			typed := len(objective.Requirements) > 0
			for _, action := range objective.CandidateActions {
				if action == definition.Type {
					if typed {
						typedCandidateSeen = true
						missing := missingRequirements(objective)
						matches := capabilityMatches(definition.Capabilities, missing)
						if len(matches) == 0 {
							dispositions = append(dispositions, CandidateDisposition{ActionType: definition.Type, ObjectiveID: objective.ID, Status: "unsupported", Reason: "action capabilities do not cover any missing typed requirement"})
							continue
						}
						capabilityMatch += len(matches)
					}
					objectiveMatch++
					if selectedObjective == nil || objectivePriority(objective, definition.Type) > objectivePriority(*selectedObjective, definition.Type) {
						candidate := objective
						selectedObjective = &candidate
					}
				}
			}
		}
		if unresolved == 0 {
			continue
		}
		if typedCandidateSeen && selectedObjective == nil {
			continue
		}
		objectiveID := ""
		input := ActionInput{InvestigationID: state.InvestigationID}
		if selectedObjective != nil {
			objectiveID = selectedObjective.ID
			input = objectiveActionInput(state.InvestigationID, *selectedObjective)
		}
		if selectedObjective != nil && len(selectedObjective.Requirements) > 0 && (selectedObjective.Target == "" || selectedObjective.TargetSymbol == "") {
			dispositions = append(dispositions, CandidateDisposition{ActionType: definition.Type, ObjectiveID: selectedObjective.ID, Status: "blocked/unavailable", Reason: "typed objective has no verified target or symbol"})
			continue
		}
		if completed(state, definition.Type, objectiveID, input) {
			continue
		}
		score := ActionScore{DiagnosticRelevance: float64(unresolved), UncertaintyReduction: 1 + float64(objectiveMatch), Discrimination: .5, EvidenceQuality: 1, ExecutionCost: 1, ExecutionRisk: 1, ExpectedLatency: 1}
		if capabilityMatch > 0 {
			score.UncertaintyReduction += float64(capabilityMatch)
		}
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
		considered = append(considered, ActionCandidate{ActionType: definition.Type, ObjectiveID: objectiveID, Input: input, Score: score, Reason: fmt.Sprintf("%d unresolved objective(s), %d matching predicates, %d missing requirements covered; expected information gain %.2f at cost %.2f", unresolved, objectiveMatch, capabilityMatch, score.UncertaintyReduction, score.ExecutionCost), Disposition: "eligible"})
	}
	if len(considered) == 0 {
		return Decision{StoppingReason: "no capable action remains", Dispositions: dispositions}
	}
	sort.SliceStable(considered, func(i, j int) bool { return considered[i].Score.Total > considered[j].Score.Total })
	return Decision{Selected: considered[0], Considered: considered, Dispositions: dispositions}
}

func missingRequirements(objective domain.AdaptiveObjective) []domain.EvidenceRequirement {
	if len(objective.Requirements) == 0 {
		return nil
	}
	if len(objective.MissingRequirements) == 0 {
		return objective.Requirements
	}
	missing := make([]domain.EvidenceRequirement, 0, len(objective.Requirements))
	for _, requirement := range objective.Requirements {
		label := requirement.ClaimKind
		if requirement.Ordering != "" {
			label += " (" + requirement.Ordering + ")"
		}
		found := false
		for _, value := range objective.MissingRequirements {
			if value == requirement.ClaimKind || value == label || strings.HasPrefix(value, requirement.ClaimKind+" ") {
				found = true
				break
			}
		}
		if found {
			missing = append(missing, requirement)
		}
	}
	return missing
}

func capabilityMatches(capabilities []EvidenceCapability, requirements []domain.EvidenceRequirement) []EvidenceCapability {
	var matches []EvidenceCapability
	for _, requirement := range requirements {
		for _, capability := range capabilities {
			if capability.ClaimKind != requirement.ClaimKind || basisRank(capability.MinimumBasis) < basisRank(requirement.MinimumBasis) {
				continue
			}
			if requirement.Subject != "" && capability.SubjectScope == "" {
				continue
			}
			if requirement.Ordering != "" && !capability.SupportsOrdering {
				continue
			}
			if requirement.SameInstance && !capability.SupportsRuntimeInstance {
				continue
			}
			matches = append(matches, capability)
		}
	}
	return matches
}

func basisRank(value string) int {
	switch value {
	case "Observed", "Inferred":
		return 1
	case "SourceVerified":
		return 2
	case "RuntimeObserved":
		return 3
	case "Experimental":
		return 4
	default:
		return 0
	}
}
func objectivePriority(objective domain.AdaptiveObjective, actionType string) int {
	priority := 0
	if objective.NextAction == actionType {
		priority += 2
	}
	if objective.Target != "" || objective.TargetSymbol != "" {
		priority++
	}
	return priority
}

func objectiveActionInput(investigationID domain.ID, objective domain.AdaptiveObjective) ActionInput {
	input := ActionInput{InvestigationID: investigationID, Metadata: map[string]string{
		"objective_id":      objective.ID,
		"predicate":         objective.Predicate,
		"required_evidence": strings.Join(objective.RequiredEvidence, ","),
	}}
	if objective.Target != "" {
		input.References = []string{objective.Target}
		input.Metadata["target"] = objective.Target
	}
	if objective.TargetSymbol != "" {
		input.Metadata["target_symbol"] = objective.TargetSymbol
	}
	return input
}

func completed(state State, kind, objectiveID string, input ActionInput) bool {
	for _, a := range state.Activities {
		// Source-stage activities carry input targets and must not block a later
		// adaptive action of the same kind. Adaptive activities are identified by
		// their durable ID, not by whether they have input references: adaptive
		// targets are required for provenance and therefore are non-empty.
		adaptive := strings.Contains(a.ID, ":adaptive:")
		if a.Type != kind || a.Status != domain.ActivityCompleted {
			continue
		}
		if !adaptive && len(a.InputRefs) == 0 {
			return true
		}
		if !adaptive {
			continue
		}
		if a.ObjectiveID != objectiveID {
			continue
		}
		if len(input.References) > 0 && equalStrings(a.InputRefs, input.References) {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
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
