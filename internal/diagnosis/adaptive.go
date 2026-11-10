package diagnosis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/execution"
	"github.com/causent/malenia/internal/investigation"
	"github.com/causent/malenia/internal/localization"
	"github.com/causent/malenia/internal/persistence"
	"github.com/causent/malenia/internal/reasoning"
	programrepo "github.com/causent/malenia/internal/repository"
)

// rerunAction is intentionally narrow: it can only rerun the already approved
// diagnosis command through the configured Executor. It cannot execute model
// generated shell, access secrets, or escape the existing isolated workspace.
type rerunAction struct {
	diagnoser *Diagnoser
	workspace string
	kind      string
}

func (a rerunAction) Type() string {
	if a.kind != "" {
		return a.kind
	}
	return "RerunFailingTest"
}
func (a rerunAction) Definition() investigation.ActionDefinition {
	return investigation.ActionDefinition{ID: strings.ToLower(a.Type()) + "-v1", Type: a.Type(), Description: "run the configured failing command in the isolated revision", InputSchema: "investigation_id", OutputSchema: "evidence_ids", RequiredEvidence: []string{"failure_episode"}, Preconditions: []string{"isolated_workspace", "configured_command"}, ResourceRequirements: map[string]string{"network": "denied-by-executor-policy"}, ExecutionRisk: "medium", Timeout: a.diagnoser.cfg.Timeout, RetryLimit: 0, Idempotent: true}
}
func (a rerunAction) Execute(ctx context.Context, input investigation.ActionInput) (investigation.ActionOutput, error) {
	started := time.Now().UTC()
	res, err := a.diagnoser.cfg.Executor.Run(ctx, execution.Request{Command: a.diagnoser.cfg.Command, Dir: a.workspace, Timeout: a.diagnoser.cfg.Timeout, MaxOutput: 64 << 10})
	payload := fmt.Sprintf("exit_code=%d timed_out=%t duration=%s\nstdout=%s\nstderr=%s", res.ExitCode, res.TimedOut, res.Duration, bound(res.Stdout, MaxEvidenceExcerpt), bound(res.Stderr, MaxEvidenceExcerpt))
	hash := sha256.Sum256([]byte(payload))
	evidence := domain.Evidence{ID: domain.ID("evidence:adaptive:" + hex.EncodeToString(hash[:8])), InvestigationID: input.InvestigationID, Type: domain.EvidenceReproduction, Source: "adaptive:RerunFailingTest", Timestamp: started, ContentRef: "adaptive-rerun", Digest: hex.EncodeToString(hash[:]), Payload: payload, Provenance: "controlled action; configured command; isolated workspace"}
	if err != nil {
		evidence.Payload += "\nexecutor_error=" + err.Error()
		return investigation.ActionOutput{Evidence: []domain.Evidence{evidence}}, err
	}
	return investigation.ActionOutput{References: []string{string(evidence.ID)}, Evidence: []domain.Evidence{evidence}, Metadata: map[string]string{"outcome": adaptiveOutcome(res)}}, nil
}

func adaptiveOutcome(res domain.ExecutionResult) string {
	if res.Error != "" || res.TimedOut {
		return "inconclusive"
	}
	if res.ExitCode == 0 {
		return "contradicts"
	}
	return "supports"
}

// runAdaptiveLoop repeatedly loads durable state, selects one eligible action,
// executes it, feeds its evidence back into reasoning, and checkpoints before
// deciding whether another iteration is justified.
func (d *Diagnoser) runAdaptiveLoop(ctx context.Context, report *Report, workspace string) error {
	if d.cfg.Store == nil {
		report.StoppingReason = "execution_unavailable"
		ensureTerminalInvestigation(report, report.StoppingReason, domain.InvestigationBudget{})
		return nil
	}
	invID := domain.ID(report.InvestigationID)
	budget := domain.InvestigationBudget{MaxIterations: d.cfg.AdaptiveMaxIterations, MaxActivities: d.cfg.AdaptiveMaxActivities, MaxExperiments: d.cfg.AdaptiveMaxExperiments, MaxDuration: d.cfg.AdaptiveTimeout}
	state := domain.AdaptiveState{InvestigationID: invID, Budget: budget, UpdatedAt: time.Now().UTC()}
	if prior, err := d.cfg.Store.GetAdaptiveState(invID); err == nil {
		state.Iterations = prior.Iterations
		state.Questions = prior.Questions
		if report.InvestigationObjective == nil && len(prior.Objectives) > 0 {
			report.InvestigationObjective = objectiveFromCheckpoint(prior.Objectives)
		}
		state.Budget = budget
		state.TerminalExplanation = prior.TerminalExplanation
	}
	registry := investigation.NewRegistry()
	register := func(action investigation.Action) error { return registry.Register(action) }
	for _, kind := range []string{"InspectSymbol", "InspectFunction", "TraceVariable", "FindReferences", "InspectGoroutineLifecycle", "InspectSynchronization", "InspectCleanup", "TraceCallers", "TraceCallees", "ExpandCallers", "ExpandCallees", "InspectDependency", "InspectTest"} {
		if err := register(repositoryAction{diagnoser: d, workspace: workspace, kind: kind, target: firstCandidateSymbol(report)}); err != nil {
			return err
		}
	}
	if report.NormalizedEvidence == nil {
		if err := register(rerunAction{diagnoser: d, workspace: workspace, kind: "RunTargetedTest"}); err != nil {
			return err
		}
		if err := register(rerunAction{diagnoser: d, workspace: workspace}); err != nil {
			return err
		}
	}
	if d.cfg.BaseRef != "" && report.NormalizedEvidence == nil {
		if err := register(compareRevisionsAction{diagnoser: d, baseline: report.Baseline, headCommit: report.Environment.HeadCommit, kind: "CompareRevisions"}); err != nil {
			return err
		}
	}
	activities, err := d.cfg.Store.ListActivities(invID)
	if err != nil {
		return err
	}
	experiments, err := d.cfg.Store.ListExperiments(invID)
	if err != nil {
		return err
	}
	// Architecture stages are prerequisites, not adaptive budget consumption.
	for _, activity := range activities {
		if strings.Contains(string(activity.ID), ":adaptive:") && activity.Status == domain.ActivityCompleted {
			state.Budget.ActivitiesUsed++
		}
	}
	for _, experiment := range experiments {
		if strings.HasPrefix(string(experiment.ID), "experiment:adaptive:") && experiment.State != domain.ExperimentPlanned {
			state.Budget.ExperimentsUsed++
		}
	}
	// A process can die after marking an activity running. Preserve it as a
	// retryable failure; idempotent actions can then be selected again.
	for i := range activities {
		if activities[i].Status == domain.ActivityRunning {
			activities[i] = investigation.Fail(activities[i], fmt.Errorf("interrupted before completion; retryable action"))
			if err := d.cfg.Store.SaveActivity(activities[i]); err != nil {
				return err
			}
		}
	}
	currentActivities, currentExperiments := activities, experiments
	start := time.Now()
	for !investigation.TimedOut(start, state.Budget) {
		if report.InvestigationObjective != nil {
			evaluateInvestigationObjectives(report)
			if err := saveAdaptiveObjectives(d.cfg.Store, report, &state); err != nil {
				return err
			}
			if causalContractSatisfied(report) {
				state.StoppingReason = "root_cause_established"
				break
			}
		}
		state.Questions = questionsFor(report.Hypotheses)
		report.UnresolvedQuestions = state.Questions
		state.Budget.IterationsUsed = state.Iterations
		decision := investigation.Select(investigation.State{InvestigationID: invID, Hypotheses: report.Hypotheses, Objectives: state.Objectives, Questions: state.Questions, Activities: currentActivities, Experiments: currentExperiments, Budget: state.Budget}, registry, investigation.DefaultScorePolicy)
		if decision.StoppingReason != "" {
			if strings.Contains(strings.ToLower(decision.StoppingReason), "budget") {
				state.StoppingReason = "budget_exhausted"
				if report.InvestigationObjective != nil && !causalContractSatisfied(report) {
					report.InvestigationObjective.StoppingReason = "adaptive investigation budget was exhausted: " + decision.StoppingReason
				}
			} else if report.InvestigationObjective != nil && !causalContractSatisfied(report) {
				state.StoppingReason = "investigation_blocked"
				report.InvestigationObjective.StoppingReason = "controller had no eligible useful action: " + decision.StoppingReason
			} else {
				state.StoppingReason = decision.StoppingReason
			}
			break
		}
		decision.Selected.Input.InvestigationID = invID
		if isRepositoryInspectionAction(decision.Selected.ActionType) {
			target, symbol := adaptiveTargetForObjective(report, decision.Selected.ObjectiveID, d.snapshot)
			if target == "" {
				state.StoppingReason = "execution_unavailable"
				if report.InvestigationObjective != nil {
					report.InvestigationObjective.StoppingReason = "selected source action has no resolvable source target"
				}
				break
			}
			decision.Selected.Input.References = []string{target}
			decision.Selected.Input.Metadata = map[string]string{"target_symbol": symbol}
		}
		activity := investigation.NewActivity(invID, "activity:"+report.InvestigationID+":adaptive:"+fmt.Sprint(state.Iterations+1), decision.Selected.ActionType, nil, decision.Selected.Input.References)
		activity.Status = domain.ActivityRunning
		activity.AttemptCount = 1
		activity.SelectionReason = decision.Selected.Reason
		if err := d.cfg.Store.SaveActivity(activity); err != nil {
			return err
		}
		out, execErr := investigation.Execute(ctx, investigation.State{InvestigationID: invID}, registry, decision)
		if execErr != nil && len(out.Evidence) == 0 {
			failed := investigation.Fail(activity, execErr)
			_ = d.cfg.Store.SaveActivity(failed)
			state.StoppingReason = "execution_unavailable"
			if report.InvestigationObjective != nil {
				report.InvestigationObjective.StoppingReason = "selected action failed: " + execErr.Error()
			}
			break
		}
		newEvidence := adaptiveProducesNewEvidence(report, out.Evidence)
		for _, evidence := range out.Evidence {
			if err := d.cfg.Store.SaveEvidence(evidence); err != nil {
				return fmt.Errorf("save adaptive evidence: %w", err)
			}
			report.Evidence = append(report.Evidence, EvidenceItem{ID: string(evidence.ID), Kind: string(evidence.Type), Source: evidence.Source, Digest: evidence.Digest, Detail: evidence.Payload, Provenance: evidence.Provenance, Revision: report.Environment.HeadCommit})
		}
		completed := investigation.Complete(activity, out.References)
		if execErr != nil {
			completed.Error = execErr.Error()
		}
		if err := d.cfg.Store.SaveActivity(completed); err != nil {
			return err
		}
		var ex domain.Experiment
		if isExperimentAction(decision.Selected.ActionType) {
			ex = domain.Experiment{ID: domain.ID("experiment:adaptive:" + fmt.Sprint(state.Iterations+1)), InvestigationID: invID, Type: domain.ExpRunReproduction, Purpose: domain.PurposeDistinguish, Command: d.cfg.Command, WorkingDir: workspace, HypothesesIDs: hypothesisIDs(report.Hypotheses), Timeout: d.cfg.Timeout, MaxOutput: 64 << 10, Status: domain.StatusCompleted, State: domain.ExperimentCompleted, Outcome: outcomeFromMetadata(out.Metadata), EvidenceProduced: evidenceIDs(out.Evidence), CreatedAt: time.Now().UTC(), FinishedAt: timePtr(time.Now().UTC()), SelectionReason: decision.Selected.Reason, Description: "adaptive controlled investigation action"}
			if execErr != nil {
				ex.Status, ex.State, ex.Outcome, ex.Error = domain.StatusInconclusive, domain.ExperimentInconclusive, domain.OutcomeInconclusive, execErr.Error()
			}
			if err := d.cfg.Store.SaveExperiment(ex); err != nil {
				return fmt.Errorf("save adaptive experiment: %w", err)
			}
			report.Experiments = append(report.Experiments, ex)
		}
		if len(out.Evidence) > 0 && out.Metadata["dimension"] == "runtime" {
			ids := evidenceIDs(out.Evidence)
			report.Candidates = localization.ApplyRuntimeEvidence(report.Candidates, ids)
			for _, c := range report.Candidates {
				if err := d.cfg.Store.SaveCandidate(c); err != nil {
					return fmt.Errorf("save adaptive candidate: %w", err)
				}
			}
		}
		if len(out.Evidence) > 0 && !newEvidence {
			out.Metadata["progress"] = "none"
			if report.InvestigationObjective != nil && decision.Selected.ObjectiveID != "" {
				for i := range report.InvestigationObjective.Unknowns {
					if report.InvestigationObjective.Unknowns[i].ID == decision.Selected.ObjectiveID {
						report.InvestigationObjective.Unknowns[i].Evaluation = "action returned no new evidence or relationships; dependency remains unresolved"
					}
				}
			}
		}
		if ex.ID != "" {
			if err := d.reassessHypotheses(report, out.Evidence, ex); err != nil {
				return fmt.Errorf("reassess adaptive hypotheses: %w", err)
			}
		} else if len(out.Evidence) > 0 {
			if err := d.reassessSourceHypotheses(report, out.Evidence, decision.Selected.ActionType); err != nil {
				return fmt.Errorf("reassess source hypotheses: %w", err)
			}
		}
		state.Iterations++
		state.Budget.IterationsUsed = state.Iterations
		state.Budget.ActivitiesUsed++
		if ex.ID != "" {
			state.Budget.ExperimentsUsed++
		}
		currentActivities = append(currentActivities, completed)
		currentExperiments = append(currentExperiments, ex)
		if err := saveAdaptiveObjectives(d.cfg.Store, report, &state); err != nil {
			return err
		}
		state.StoppingReason = ""
	}
	if state.StoppingReason == "" {
		state.StoppingReason = "budget_exhausted"
		if report.InvestigationObjective != nil && !causalContractSatisfied(report) {
			report.InvestigationObjective.StoppingReason = "adaptive investigation duration or budget was exhausted"
		}
	}
	state.StoppingReason = canonicalStoppingReason(state.StoppingReason)
	if report.InvestigationObjective != nil {
		switch {
		case causalContractSatisfied(report):
			report.InvestigationObjective.Status = "resolved"
			report.InvestigationObjective.StoppingReason = "root cause contract satisfied"
		case allObjectivesResolved(report):
			report.InvestigationObjective.Status = "resolved"
			report.InvestigationObjective.StoppingReason = "all objective predicates resolved; causal contract remains incomplete"
		case strings.HasPrefix(state.StoppingReason, "budget_exhausted"):
			report.InvestigationObjective.Status = "blocked"
			report.InvestigationObjective.StoppingReason = state.StoppingReason
		default:
			report.InvestigationObjective.Status = "blocked"
			report.InvestigationObjective.StoppingReason = state.StoppingReason
		}
	}
	state.UpdatedAt = time.Now().UTC()
	report.StoppingReason, report.AdaptiveIterations = state.StoppingReason, state.Iterations
	for _, activity := range currentActivities {
		if activity.Status != domain.ActivityCompleted && activity.Status != domain.ActivityFailed {
			continue
		}
		seen := false
		for _, action := range report.InvestigationActions {
			if action.ID == activity.ID {
				seen = true
				break
			}
		}
		if !seen {
			report.InvestigationActions = append(report.InvestigationActions, InvestigationAction{ID: activity.ID, Type: activity.Type, Target: strings.Join(activity.InputRefs, ","), Status: string(activity.Status), Summary: activity.SelectionReason, EvidenceIDs: activity.OutputRefs})
		}
	}
	ensureTerminalInvestigation(report, state.StoppingReason, state.Budget)
	state.TerminalExplanation = report.TerminalInvestigation
	return d.cfg.Store.SaveAdaptiveState(state)
}

func canonicalStoppingReason(reason string) string {
	switch reason {
	case "root_cause_established", "investigation_blocked", "budget_exhausted", "execution_unavailable", "user_cancelled":
		return reason
	default:
		if strings.Contains(reason, "budget") {
			return "budget_exhausted"
		}
		return "investigation_blocked"
	}
}

// ensureTerminalInvestigation materializes the stop decision as structured
// state. A string stopping reason is insufficient because it cannot explain
// whether an unresolved dependency was unavailable, blocked, or simply left
// behind by the budget.
func ensureTerminalInvestigation(report *Report, reason string, budget domain.InvestigationBudget) {
	if reason == "" {
		reason = "investigation_blocked"
	}
	terminal := &domain.TerminalInvestigationState{
		Reason:  reason,
		Budget:  budget,
		Summary: "investigation stopped before all causal dependencies were established",
	}
	if reason == "root_cause_established" {
		terminal.Summary = "causal contract satisfied and investigation terminated"
	} else if reason == "budget_exhausted" {
		terminal.Summary = "investigation stopped because the configured budget was exhausted"
	} else if reason == "execution_unavailable" {
		terminal.Summary = "investigation stopped because required execution or persistence was unavailable"
	}
	if report.InvestigationObjective != nil {
		attempted := map[string]bool{}
		for _, action := range report.InvestigationActions {
			attempted[action.Type] = true
		}
		for _, unknown := range report.InvestigationObjective.Unknowns {
			if unknown.Status == "resolved" {
				continue
			}
			terminal.UnresolvedDependencies = append(terminal.UnresolvedDependencies, domain.InvestigationDependency{
				ID: unknown.ID, Predicate: unknown.Predicate, Status: unknown.Status,
				RequiredEvidence: append([]string(nil), unknown.RequiredKinds...),
				Evaluation:       unknown.Evaluation, NextAction: unknown.NextAction,
			})
			for _, action := range unknown.CandidateActions {
				if attempted[action] {
					continue
				}
				status, explanation := "blocked", "dependency remained unresolved when the controller stopped"
				switch reason {
				case "execution_unavailable":
					status, explanation = "unavailable", "the execution or persistence capability required by this action was unavailable"
				case "budget_exhausted":
					status, explanation = "excluded_by_budget", "the action was useful but could not be selected after the budget was exhausted"
				}
				terminal.ActionsNotAttempted = appendUniqueDisposition(terminal.ActionsNotAttempted, domain.InvestigationDisposition{
					ActionType: action, Status: status, Reason: explanation, UnknownIDs: []string{unknown.ID},
				})
			}
		}
	}
	if reason == "root_cause_established" {
		terminal.UnresolvedDependencies = nil
		terminal.ActionsNotAttempted = nil
	}
	report.TerminalInvestigation = terminal
}

func appendUniqueDisposition(values []domain.InvestigationDisposition, value domain.InvestigationDisposition) []domain.InvestigationDisposition {
	for _, existing := range values {
		if existing.ActionType == value.ActionType && existing.Status == value.Status && strings.Join(existing.UnknownIDs, ",") == strings.Join(value.UnknownIDs, ",") {
			return values
		}
	}
	return append(values, value)
}

func allObjectivesResolved(report *Report) bool {
	if report.InvestigationObjective == nil || len(report.InvestigationObjective.Unknowns) == 0 {
		return false
	}
	for _, unknown := range report.InvestigationObjective.Unknowns {
		if unknown.Status != "resolved" {
			return false
		}
	}
	return true
}

func objectiveFromCheckpoint(values []domain.AdaptiveObjective) *InvestigationObjective {
	if len(values) == 0 {
		return nil
	}
	out := &InvestigationObjective{FailureObjective: "Resume the persisted causal investigation", Status: "investigating"}
	for _, value := range values {
		out.Unknowns = append(out.Unknowns, InvestigationUnknown{ID: value.ID, Question: value.Question, Predicate: value.Predicate, Status: value.Status, EvidenceIDs: domainIDsToStrings(value.EvidenceIDs), ResolutionIDs: domainIDsToStrings(value.ResolutionEvidence), Evaluation: value.Evaluation, Revision: value.Revision, NextAction: value.NextAction, CandidateActions: append([]string(nil), value.CandidateActions...), Target: value.Target, TargetSymbol: value.TargetSymbol})
	}
	return out
}

func domainIDsToStrings(values []domain.ID) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func saveAdaptiveObjectives(store *persistence.Store, report *Report, state *domain.AdaptiveState) error {
	if report.InvestigationObjective == nil {
		return nil
	}
	state.Objectives = make([]domain.AdaptiveObjective, 0, len(report.InvestigationObjective.Unknowns))
	for _, unknown := range report.InvestigationObjective.Unknowns {
		state.Objectives = append(state.Objectives, domain.AdaptiveObjective{ID: unknown.ID, Question: unknown.Question, Predicate: unknown.Predicate, Status: unknown.Status, EvidenceIDs: stringIDsToDomain(unknown.EvidenceIDs), ResolutionEvidence: stringIDsToDomain(unknown.ResolutionIDs), Evaluation: unknown.Evaluation, Revision: unknown.Revision, NextAction: unknown.NextAction, CandidateActions: append([]string(nil), unknown.CandidateActions...), Target: unknown.Target, TargetSymbol: unknown.TargetSymbol})
	}
	state.UpdatedAt = time.Now().UTC()
	return store.SaveAdaptiveState(*state)
}

func (d *Diagnoser) reassessHypotheses(report *Report, evidence []domain.Evidence, ex domain.Experiment) error {
	evidenceMap := map[domain.ID]domain.Evidence{}
	for _, e := range evidence {
		evidenceMap[e.ID] = e
	}
	for i := range report.Hypotheses {
		before := report.Hypotheses[i]
		next := before
		for _, e := range evidence {
			if ex.Outcome == domain.OutcomeSupports {
				next.SupportingEvidenceIDs = appendUnique(next.SupportingEvidenceIDs, e.ID)
			} else if ex.Outcome == domain.OutcomeContradicts {
				next.ContradictingEvidenceIDs = appendUnique(next.ContradictingEvidenceIDs, e.ID)
			}
		}
		next.ExperimentIDs = appendUnique(next.ExperimentIDs, ex.ID)
		next = reasoning.Assess(next, evidenceMap, nil, map[domain.ID]domain.Experiment{ex.ID: ex}).Hypothesis
		next = reasoning.Version(next, &before)
		report.Hypotheses[i] = next
		if err := d.cfg.Store.SaveHypothesis(next); err != nil {
			return err
		}
		if err := d.cfg.Store.SaveHypothesisHistory(domain.HypothesisHistory{ID: domain.NewID(), HypothesisID: next.ID, InvestigationID: next.InvestigationID, PreviousStatus: before.Status, NextStatus: next.Status, PreviousConfidence: before.Confidence, NextConfidence: next.Confidence, ExperimentID: ex.ID, Evaluation: "adaptive evidence reassessment", CreatedAt: time.Now().UTC()}); err != nil {
			return err
		}
		for j := range report.Findings {
			if report.Findings[j].HypothesisID == before.ID {
				report.Findings[j].HypothesisID = next.ID
				report.Findings[j].Status = string(next.Status)
				report.Findings[j].EvidenceIDs = appendUnique(report.Findings[j].EvidenceIDs, evidenceIDs(evidence)...)
				report.Findings[j].Uncertainty = next.MissingEvidence
				if err := d.cfg.Store.SaveFinding(report.Findings[j]); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (d *Diagnoser) reassessSourceHypotheses(report *Report, evidence []domain.Evidence, actionType string) error {
	for index := range report.Hypotheses {
		before := report.Hypotheses[index]
		next := before
		relevant := false
		switch {
		case strings.Contains(strings.ToLower(string(before.AffectedComponent)), "lifecycle"):
			relevant = actionType == "InspectGoroutineLifecycle" || actionType == "InspectCleanup" || actionType == "InspectSynchronization" || actionType == "TraceCallees"
		case strings.Contains(strings.ToLower(string(before.AffectedComponent)), "memory"):
			relevant = actionType == "InspectFunction" || actionType == "TraceVariable" || actionType == "FindReferences" || actionType == "InspectSymbol"
		}
		if !relevant {
			continue
		}
		for _, item := range evidence {
			if containsAny(strings.ToLower(item.Payload), "verified happens-before", "ordering established") && strings.Contains(strings.ToLower(string(before.AffectedComponent)), "lifecycle") {
				next.ContradictingEvidenceIDs = appendUnique(next.ContradictingEvidenceIDs, item.ID)
			} else {
				next.SupportingEvidenceIDs = appendUnique(next.SupportingEvidenceIDs, item.ID)
			}
		}
		next.MissingEvidence = append([]string(nil), before.MissingEvidence...)
		next.UpdatedAt = time.Now().UTC()
		next = reasoning.Assess(next, evidenceMapFromReport(report), nil, nil).Hypothesis
		next = reasoning.Version(next, &before)
		report.Hypotheses[index] = next
		if err := d.cfg.Store.SaveHypothesis(next); err != nil {
			return err
		}
		if err := d.cfg.Store.SaveHypothesisHistory(domain.HypothesisHistory{ID: domain.NewID(), HypothesisID: next.ID, InvestigationID: next.InvestigationID, PreviousStatus: before.Status, NextStatus: next.Status, PreviousConfidence: before.Confidence, NextConfidence: next.Confidence, Evaluation: "adaptive source evidence reassessment", CreatedAt: time.Now().UTC()}); err != nil {
			return err
		}
	}
	return nil
}

func evidenceMapFromReport(report *Report) map[domain.ID]domain.Evidence {
	out := make(map[domain.ID]domain.Evidence, len(report.Evidence))
	for _, item := range report.Evidence {
		out[domain.ID(item.ID)] = domain.Evidence{ID: domain.ID(item.ID), InvestigationID: domain.ID(report.InvestigationID), Type: domain.EvidenceType(item.Kind), Source: item.Source, Digest: item.Digest, Payload: item.Detail, Provenance: item.Provenance}
	}
	return out
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func hypothesisIDs(values []domain.Hypothesis) []domain.ID {
	out := make([]domain.ID, 0, len(values))
	for _, h := range values {
		out = append(out, h.ID)
	}
	return out
}
func evidenceIDs(values []domain.Evidence) []domain.ID {
	out := make([]domain.ID, 0, len(values))
	for _, e := range values {
		out = append(out, e.ID)
	}
	return out
}
func appendUnique(values []domain.ID, extra ...domain.ID) []domain.ID {
	for _, value := range extra {
		found := false
		for _, v := range values {
			if v == value {
				found = true
				break
			}
		}
		if !found && value != "" {
			values = append(values, value)
		}
	}
	return values
}
func outcomeFromMetadata(m map[string]string) domain.ExperimentOutcome {
	switch strings.ToLower(m["outcome"]) {
	case "supports":
		return domain.OutcomeSupports
	case "contradicts":
		return domain.OutcomeContradicts
	default:
		return domain.OutcomeInconclusive
	}
}
func timePtr(t time.Time) *time.Time { return &t }

func firstCandidateSymbol(report *Report) string {
	if len(report.Candidates) == 0 {
		return ""
	}
	return report.Candidates[0].Location.SymbolIdentity
}

func adaptiveTargetForObjective(report *Report, objectiveID string, snapshot *programrepo.Snapshot) (string, string) {
	if report.InvestigationObjective != nil {
		for _, unknown := range report.InvestigationObjective.Unknowns {
			if unknown.ID != objectiveID {
				continue
			}
			if unknown.Target != "" && unknown.TargetSymbol != "" {
				if snapshot != nil {
					for _, node := range snapshot.Nodes {
						if node.Identity == unknown.TargetSymbol {
							return fmt.Sprintf("%s:%d:%s", node.FilePath, node.StartLine, node.Identity), node.Identity
						}
					}
				}
				return unknown.Target, unknown.TargetSymbol
			}
		}
	}
	if target := adaptiveActionTarget(report); target != "" {
		return target, firstCandidateSymbol(report)
	}
	return "", ""
}

func adaptiveProducesNewEvidence(report *Report, evidence []domain.Evidence) bool {
	known := map[string]bool{}
	for _, item := range report.Evidence {
		known[item.ID] = true
	}
	for _, item := range evidence {
		if !known[string(item.ID)] {
			return true
		}
	}
	return false
}

func adaptiveActionTarget(report *Report) string {
	if len(report.Candidates) == 0 {
		return ""
	}
	location := report.Candidates[0].Location
	if location.SymbolIdentity == "" || location.FilePath == "" {
		return ""
	}
	target := location.FilePath
	if location.StartLine > 0 {
		target += ":" + fmt.Sprint(location.StartLine)
	}
	return target + ":" + location.SymbolIdentity
}

func isRepositoryInspectionAction(kind string) bool {
	switch kind {
	case "InspectSymbol", "InspectFunction", "TraceVariable", "FindReferences", "InspectGoroutineLifecycle", "InspectSynchronization", "InspectCleanup", "TraceCallers", "TraceCallees", "ExpandCallers", "ExpandCallees", "InspectDependency", "InspectTest":
		return true
	default:
		return false
	}
}

func isAdaptiveActivity(kind string) bool {
	switch kind {
	case "InspectSymbol", "InspectFunction", "TraceVariable", "FindReferences", "InspectGoroutineLifecycle", "InspectSynchronization", "InspectCleanup", "TraceCallers", "TraceCallees", "ExpandCallers", "ExpandCallees", "InspectDependency", "InspectTest", "RunTargetedTest", "RerunFailingTest", "CompareBaseAndHead", "CompareRevisions":
		return true
	default:
		return false
	}
}

func isExperimentAction(kind string) bool {
	switch kind {
	case "RunTargetedTest", "RerunFailingTest", "CompareBaseAndHead", "CompareRevisions":
		return true
	default:
		return false
	}
}

func questionsFor(hypotheses []domain.Hypothesis) []domain.InvestigationQuestion {
	var out []domain.InvestigationQuestion
	for _, h := range hypotheses {
		switch h.Status {
		case domain.HypProposed, domain.HypUnderInvestigation, domain.HypInconclusive, domain.HypWeakened:
			out = append(out, domain.InvestigationQuestion{ID: "question:" + string(h.ID), Statement: "What observation distinguishes: " + h.Statement + "?", HypothesisIDs: []domain.ID{h.ID}, MissingEvidence: h.SupportingEvidenceIDs})
		}
	}
	return out
}

var _ investigation.Action = rerunAction{}

// ResumeIncomplete reloads durable investigations and re-enters the normal
// diagnosis lifecycle with the same investigation IDs. Existing activities,
// experiments, evidence, and adaptive checkpoints are reused; completed
// actions are not executed again.
func ResumeIncomplete(ctx context.Context, store *persistence.Store, base Config) ([]Report, error) {
	if store == nil {
		return nil, fmt.Errorf("store is required")
	}
	incomplete, err := store.ListIncompleteInvestigations()
	if err != nil {
		return nil, err
	}
	reports := make([]Report, 0, len(incomplete))
	for _, inv := range incomplete {
		cfg := base
		cfg.Store = store
		cfg.InvestigationID = string(inv.ID)
		cfg.RepoPath = inv.RepoPath
		cfg.Command = inv.Command
		report, runErr := Run(ctx, cfg)
		if runErr != nil {
			return reports, runErr
		}
		reports = append(reports, report)
	}
	return reports, nil
}
