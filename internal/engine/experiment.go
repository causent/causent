package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/causent/causent/internal/domain"
	"github.com/causent/causent/internal/execution"
)

var ErrInsufficientEvidence = fmt.Errorf("insufficient evidence for a discriminating experiment")

// ExperimentPlanner deterministically selects one bounded, read-only Python
// probe. It never accepts a model-generated executable or working directory.
type ExperimentPlanner struct{}

func (ExperimentPlanner) Plan(inv domain.Investigation, hypotheses []domain.Hypothesis, evidence []domain.Evidence, existing []domain.Experiment) (domain.Experiment, error) {
	if len(hypotheses) < 2 || len(evidence) == 0 {
		return domain.Experiment{}, ErrInsufficientEvidence
	}
	if len(inv.Command) == 0 {
		return domain.Experiment{}, ErrInsufficientEvidence
	}
	sourceFile := ""
	for _, ev := range evidence {
		if ev.Type == domain.EvidenceSourceCode || ev.Type == domain.EvidenceStackTrace {
			sourceFile = sourceFileFromPayload(ev.Payload)
			if sourceFile != "" {
				break
			}
		}
	}
	if sourceFile == "" {
		return domain.Experiment{}, ErrInsufficientEvidence
	}
	if filepath.IsAbs(sourceFile) {
		repoRoot, repoErr := filepath.EvalSymlinks(inv.RepoPath)
		framePath, frameErr := filepath.EvalSymlinks(sourceFile)
		if repoErr == nil && frameErr == nil {
			relative, relErr := filepath.Rel(repoRoot, framePath)
			if relErr == nil {
				sourceFile = relative
			}
		}
		if filepath.IsAbs(sourceFile) {
			relative, err := filepath.Rel(inv.RepoPath, sourceFile)
			if err != nil {
				return domain.Experiment{}, ErrInsufficientEvidence
			}
			sourceFile = relative
		}
	}
	rel := filepath.ToSlash(filepath.Clean(sourceFile))
	for _, ex := range existing {
		if strings.Contains(strings.Join(ex.Command, " "), rel) && ex.Type == domain.ExpDeterministicDiagnostic {
			return domain.Experiment{}, fmt.Errorf("equivalent experiment already exists: %s", ex.ID)
		}
	}
	if strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		return domain.Experiment{}, fmt.Errorf("source path is outside repository: %s", rel)
	}
	script := fmt.Sprintf("from pathlib import Path\np=Path(%q)\nt=p.read_text()\nprint('SOURCE_CONTEXT_PRESENT')\nprint('SOURCE_BYTES',len(t.encode()))\nprint('FIXTURE_CONTEXT_PRESENT', 'fixture' in t.lower())\n", rel)
	interpreter := inv.Command[0]
	if interpreter != "python" && interpreter != "python3" {
		return domain.Experiment{}, fmt.Errorf("no policy-approved Python interpreter in investigation command")
	}
	now := time.Now().UTC()
	ids := []domain.ID{hypotheses[0].ID, hypotheses[1].ID}
	predictions := map[domain.ID]string{
		hypotheses[0].ID: "SOURCE_CONTEXT_PRESENT and SOURCE_BYTES are observed, allowing comparison with the application-code hypothesis",
		hypotheses[1].ID: "FIXTURE_CONTEXT_PRESENT is observed if the failure is tied to fixture/test data",
	}
	return domain.Experiment{
		ID: newID(), InvestigationID: inv.ID, Type: domain.ExpDeterministicDiagnostic,
		Purpose: domain.PurposeDistinguish, HypothesesIDs: ids,
		Command: []string{interpreter, "-c", script}, WorkingDir: inv.RepoPath,
		ExpectedUnderHypothesis: predictions, Predictions: predictions,
		Timeout: 10 * time.Second, MaxOutput: 8192, Status: domain.StatusPlanningExperiment,
		State: domain.ExperimentPlanned, Description: "Inspect the failing Python source without modifying the repository and compare code versus fixture signals.",
		SelectionReason:     "The probe observes the traceback source boundary and a fixture signal instead of rerunning the same failure.",
		RequiredPermissions: []string{"read_repository", "execute_python3"},
		CreatedAt:           now,
	}, nil
}

func sourceFileFromPayload(payload string) string {
	for _, line := range strings.Split(payload, "\n") {
		if strings.Contains(line, `File "`) {
			start := strings.Index(line, `File "`) + len(`File "`)
			if end := strings.Index(line[start:], `"`); end >= 0 {
				return line[start : start+end]
			}
		}
		if strings.Contains(line, ":") && strings.Contains(line, ".py:") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				value := strings.TrimSpace(fields[0])
				if idx := strings.Index(value, ":"); idx > 0 {
					return value[:idx]
				}
			}
		}
	}
	return ""
}

func validateExperiment(inv domain.Investigation, ex domain.Experiment) error {
	if ex.InvestigationID != inv.ID || (ex.State != domain.ExperimentPlanned && ex.State != domain.ExperimentApproved) {
		return fmt.Errorf("experiment is not planned for this investigation")
	}
	if len(ex.Command) != 3 || (ex.Command[0] != "python" && ex.Command[0] != "python3") || ex.Command[1] != "-c" {
		return fmt.Errorf("experiment command is not an approved Python probe")
	}
	if len(ex.Command[2]) > 4096 || strings.Contains(ex.Command[2], "subprocess") || strings.Contains(ex.Command[2], "os.system") || strings.Contains(ex.Command[2], "write_text") {
		return fmt.Errorf("experiment probe violates read-only execution constraints")
	}
	if ex.WorkingDir != inv.RepoPath || filepath.IsAbs(ex.Command[2]) {
		return fmt.Errorf("experiment path or working directory is invalid")
	}
	if ex.Timeout <= 0 || ex.Timeout > 30*time.Second || ex.MaxOutput <= 0 || ex.MaxOutput > 64*1024 {
		return fmt.Errorf("experiment resource limits are invalid")
	}
	if len(ex.HypothesesIDs) < 2 || len(ex.Predictions) != len(ex.HypothesesIDs) {
		return fmt.Errorf("experiment must target competing hypotheses with predictions")
	}
	return nil
}

func (i *Investigator) runExperiment(ctx context.Context, inv *domain.Investigation, ex *domain.Experiment, hypotheses []domain.Hypothesis) error {
	if err := validateExperiment(*inv, *ex); err != nil {
		return err
	}
	if inv.BudgetUsed >= inv.BudgetSteps {
		return &domain.BudgetExceededError{}
	}
	if ex.State == domain.ExperimentPlanned {
		if err := i.Store.TransitionExperiment(ex.ID, inv.ID, ex.State, domain.ExperimentApproved, "validated by execution policy"); err != nil {
			return err
		}
		ex.State = domain.ExperimentApproved
		ex.Status = domain.StatusPlanningExperiment
		if err := i.Store.SaveExperiment(*ex); err != nil {
			return err
		}
	}
	if err := i.Store.TransitionExperiment(ex.ID, inv.ID, ex.State, domain.ExperimentRunning, "execution started"); err != nil {
		return err
	}

	ex.State = domain.ExperimentRunning
	ex.Status = domain.StatusRunningExperiment
	now := time.Now().UTC()
	ex.StartedAt = &now
	if err := i.Store.SaveExperiment(*ex); err != nil {
		return err
	}
	inv.BudgetUsed++
	inv.UpdatedAt = now
	if err := i.Store.SaveInvestigation(*inv); err != nil {
		return err
	}
	i.recordEvent(inv.ID, domain.StatusPlanningExperiment, domain.StatusRunningExperiment, "experiment_started", ex.ID, "", "")

	result, err := i.Executor.Run(ctx, execution.Request{Command: ex.Command, Dir: ex.WorkingDir, Timeout: ex.Timeout, MaxOutput: ex.MaxOutput})
	ex.Result = &result
	finished := time.Now().UTC()
	ex.FinishedAt = &finished
	if err != nil {
		ex.Error = err.Error()
		ex.State = domain.ExperimentFailed
		ex.Status = domain.StatusEvaluatingEvidence
		ex.Outcome = domain.OutcomeFailed
		ex.Observations = "experiment execution failed; no hypothesis prediction was evaluated"
		_ = i.Store.TransitionExperiment(ex.ID, inv.ID, domain.ExperimentRunning, ex.State, ex.Error)
		return i.Store.SaveExperiment(*ex)
	}
	ex.Observations = bounded(result.Stdout+"\n"+result.Stderr, maxInlineEvidenceBytes)
	if result.TimedOut {
		ex.State, ex.Status, ex.Outcome = domain.ExperimentInconclusive, domain.StatusEvaluatingEvidence, domain.OutcomeInconclusive
		ex.Evaluation = "execution timed out; hypotheses remain unresolved"
	} else {
		ex.State, ex.Status = domain.ExperimentCompleted, domain.StatusEvaluatingEvidence
		ex.Outcome, ex.Evaluation = evaluateExperiment(*ex, hypotheses)
	}
	ev := domain.Evidence{
		ID: newID(), InvestigationID: inv.ID, Type: domain.EvidenceSourceCode,
		Source: "experiment:" + string(ex.ID), Timestamp: finished,
		ContentRef: "experiment_observation:" + string(ex.ID), Payload: ex.Observations,
		Digest: digestString(ex.Observations), RelatedExperiments: []domain.ID{ex.ID},
		Provenance: "policy-validated experiment output",
	}
	i.attachArtifact(&ev)
	if err := i.Store.SaveEvidence(ev); err != nil {
		return err
	}
	ex.EvidenceProduced = []domain.ID{ev.ID}
	if err := i.Store.TransitionExperiment(ex.ID, inv.ID, domain.ExperimentRunning, ex.State, ex.Evaluation); err != nil {
		return err
	}
	if err := i.Store.SaveExperiment(*ex); err != nil {
		return err
	}
	i.recordEvent(inv.ID, domain.StatusRunningExperiment, domain.StatusEvaluatingEvidence, "experiment_completed", ex.ID, ev.ID, "")
	return i.updateHypothesesFromExperiment(*ex, hypotheses)
}

func (i *Investigator) ApproveExperiment(ctx context.Context, id domain.ID) error {
	ex, err := i.Store.GetExperiment(id)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := i.Store.TransitionExperiment(ex.ID, ex.InvestigationID, ex.State, domain.ExperimentApproved, "approved by operator"); err != nil {
		return err
	}
	ex.State = domain.ExperimentApproved
	return i.Store.SaveExperiment(ex)
}

func (i *Investigator) RunApprovedExperiment(ctx context.Context, id domain.ID) (domain.Experiment, error) {
	ex, err := i.Store.GetExperiment(id)
	if err != nil {
		return ex, err
	}
	inv, err := i.Store.GetInvestigation(ex.InvestigationID)
	if err != nil {
		return ex, err
	}
	hypotheses, err := i.Store.ListHypotheses(inv.ID)
	if err != nil {
		return ex, err
	}
	if ex.State != domain.ExperimentApproved {
		return ex, fmt.Errorf("experiment %s is %s, not approved", id, ex.State)
	}
	if err := i.runExperiment(ctx, &inv, &ex, hypotheses); err != nil {
		return ex, err
	}
	return ex, nil
}

func (i *Investigator) CancelExperiment(id domain.ID) error {
	ex, err := i.Store.GetExperiment(id)
	if err != nil {
		return err
	}
	if err := i.Store.TransitionExperiment(ex.ID, ex.InvestigationID, ex.State, domain.ExperimentCancelled, "cancelled by operator"); err != nil {
		return err
	}
	ex.State = domain.ExperimentCancelled
	ex.Status = domain.StatusCancelled
	ex.FinishedAt = nowPtr()
	return i.Store.SaveExperiment(ex)
}

func evaluateExperiment(ex domain.Experiment, hypotheses []domain.Hypothesis) (domain.ExperimentOutcome, string) {
	if ex.State != domain.ExperimentCompleted || strings.TrimSpace(ex.Observations) == "" {
		return domain.OutcomeInconclusive, "no completed observation was available; hypotheses remain unresolved"
	}
	supported, contradicted := 0, 0
	var lines []string
	for _, h := range hypotheses {
		prediction := ex.Predictions[h.ID]
		if prediction == "" {
			continue
		}
		matched := predictionMatches(prediction, ex.Observations)
		if matched {
			supported++
			lines = append(lines, fmt.Sprintf("%s: prediction matched", h.ID))
		} else {
			contradicted++
			lines = append(lines, fmt.Sprintf("%s: prediction not observed", h.ID))
		}
	}
	if supported == 0 && contradicted == 0 {
		return domain.OutcomeInconclusive, "no comparable predictions were available"
	}
	return domain.OutcomeSupports, strings.Join(lines, "; ")
}

func predictionMatches(prediction, observations string) bool {
	for _, marker := range []string{"SOURCE_CONTEXT_PRESENT", "FIXTURE_CONTEXT_PRESENT", "RUNTIME_VERSION_PRESENT"} {
		if strings.Contains(prediction, marker) {
			for _, line := range strings.Split(observations, "\n") {
				if strings.Contains(line, marker) {
					return !strings.Contains(marker, "FIXTURE") || strings.Contains(strings.ToLower(line), "true")
				}
			}
			return false
		}
	}
	return false
}

func (i *Investigator) updateHypothesesFromExperiment(ex domain.Experiment, hypotheses []domain.Hypothesis) error {
	for idx := range hypotheses {
		h := &hypotheses[idx]
		if !containsID(ex.HypothesesIDs, h.ID) {
			continue
		}
		previous := h.Status
		previousConfidence := h.Confidence
		prediction := ex.Predictions[h.ID]
		if prediction == "" || ex.State != domain.ExperimentCompleted {
			h.Status = domain.HypInconclusive
		} else if predictionMatches(prediction, ex.Observations) {
			h.Status = domain.HypSupported
			h.Confidence = minFloat(0.95, h.Confidence+0.1)
		} else {
			h.Status = domain.HypInconclusive
		}
		h.ExperimentIDs = appendUnique(h.ExperimentIDs, ex.ID)
		h.UpdatedAt = time.Now().UTC()
		if err := i.Store.SaveHypothesis(*h); err != nil {
			return err
		}
		if previous != h.Status || previousConfidence != h.Confidence {
			if err := i.Store.SaveHypothesisHistory(domain.HypothesisHistory{
				ID: newID(), HypothesisID: h.ID, InvestigationID: h.InvestigationID,
				PreviousStatus: previous, NextStatus: h.Status,
				PreviousConfidence: previousConfidence, NextConfidence: h.Confidence,
				ExperimentID: ex.ID, Evaluation: ex.Evaluation, CreatedAt: time.Now().UTC(),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func containsID(ids []domain.ID, target domain.ID) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}

func appendUnique(ids []domain.ID, id domain.ID) []domain.ID {
	if containsID(ids, id) {
		return ids
	}
	return append(ids, id)
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
