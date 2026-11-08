package diagnosis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/causent/causent/internal/domain"
	"github.com/causent/causent/internal/execution"
	"github.com/causent/causent/internal/investigation"
	"github.com/causent/causent/internal/localization"
	"github.com/causent/causent/internal/persistence"
	"github.com/causent/causent/internal/reasoning"
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
	if d.cfg.Store == nil || len(report.Hypotheses) == 0 {
		report.StoppingReason = "no unresolved hypotheses"
		return nil
	}
	invID := domain.ID(report.InvestigationID)
	budget := domain.InvestigationBudget{MaxIterations: d.cfg.AdaptiveMaxIterations, MaxActivities: d.cfg.AdaptiveMaxActivities, MaxExperiments: d.cfg.AdaptiveMaxExperiments, MaxDuration: d.cfg.AdaptiveTimeout}
	state := domain.AdaptiveState{InvestigationID: invID, Budget: budget, UpdatedAt: time.Now().UTC()}
	if prior, err := d.cfg.Store.GetAdaptiveState(invID); err == nil {
		state.Iterations = prior.Iterations
		state.Questions = prior.Questions
		state.Budget = budget
	}
	registry := investigation.NewRegistry()
	register := func(action investigation.Action) error { return registry.Register(action) }
	for _, kind := range []string{"InspectSymbol", "FindReferences", "ExpandCallers", "ExpandCallees", "InspectDependency", "InspectTest"} {
		if err := register(repositoryAction{diagnoser: d, workspace: workspace, kind: kind, target: firstCandidateSymbol(report)}); err != nil {
			return err
		}
	}
	if err := register(rerunAction{diagnoser: d, workspace: workspace, kind: "RunTargetedTest"}); err != nil {
		return err
	}
	if err := register(rerunAction{diagnoser: d, workspace: workspace}); err != nil {
		return err
	}
	if d.cfg.BaseRef != "" {
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
		if isAdaptiveActivity(activity.Type) && activity.Status == domain.ActivityCompleted {
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
		state.Questions = questionsFor(report.Hypotheses)
		report.UnresolvedQuestions = state.Questions
		state.Budget.IterationsUsed = state.Iterations
		decision := investigation.Select(investigation.State{InvestigationID: invID, Hypotheses: report.Hypotheses, Questions: state.Questions, Activities: currentActivities, Experiments: currentExperiments, Budget: state.Budget}, registry, investigation.DefaultScorePolicy)
		if decision.StoppingReason != "" {
			state.StoppingReason = decision.StoppingReason
			break
		}
		decision.Selected.Input.InvestigationID = invID
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
			state.StoppingReason = "selected action failed: " + execErr.Error()
			break
		}
		for _, evidence := range out.Evidence {
			if err := d.cfg.Store.SaveEvidence(evidence); err != nil {
				return fmt.Errorf("save adaptive evidence: %w", err)
			}
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
		if ex.ID != "" {
			if err := d.reassessHypotheses(report, out.Evidence, ex); err != nil {
				return fmt.Errorf("reassess adaptive hypotheses: %w", err)
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
		state.StoppingReason = ""
	}
	if state.StoppingReason == "" {
		state.StoppingReason = "adaptive duration exhausted"
	}
	state.UpdatedAt = time.Now().UTC()
	report.StoppingReason, report.AdaptiveIterations = state.StoppingReason, state.Iterations
	return d.cfg.Store.SaveAdaptiveState(state)
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

func isAdaptiveActivity(kind string) bool {
	switch kind {
	case "InspectSymbol", "FindReferences", "ExpandCallers", "ExpandCallees", "InspectDependency", "InspectTest", "RunTargetedTest", "RerunFailingTest", "CompareBaseAndHead", "CompareRevisions":
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
