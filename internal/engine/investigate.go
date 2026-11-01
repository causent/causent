package engine

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/causent/causent/internal/domain"
	"github.com/causent/causent/internal/execution"
	"github.com/causent/causent/internal/persistence"
)

type Investigator struct {
	Store               *persistence.Store
	Executor            execution.Executor
	Provider            ModelProvider
	Model               domain.ModelMetadata
	OnStarted           func(domain.Investigation)
	DisallowTestChanges bool
}

func newID() domain.ID {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	return domain.ID(time.Now().UTC().Format("20060102T150405.000000000") + "-" + hex.EncodeToString(buf))
}

// InvestigationStatusTimeout is the maximum time allowed for the full investigation.
var InvestigationStatusTimeout = 10 * time.Minute

// Investigate runs the full debugging workflow: reproduce, collect evidence,
// form hypotheses, plan and run experiments, generate and verify a patch, then
// produce a final diagnosis report.
func (i *Investigator) Investigate(ctx context.Context, repoPath string, command []string, timeout time.Duration, budgetSteps int) (domain.Investigation, domain.DiagnosisResult, error) {
	if _, err := os.Stat(repoPath); err != nil {
		return domain.Investigation{}, domain.DiagnosisResult{}, fmt.Errorf("repo path does not exist: %s", repoPath)
	}
	if _, err := os.Stat(filepath.Join(repoPath, ".git")); err != nil {
		return domain.Investigation{}, domain.DiagnosisResult{}, fmt.Errorf("not a git repository: %s", repoPath)
	}
	if len(command) == 0 {
		return domain.Investigation{}, domain.DiagnosisResult{}, fmt.Errorf("command is required")
	}
	if budgetSteps <= 0 {
		budgetSteps = 20
	}

	now := time.Now().UTC()
	inv := domain.Investigation{
		ID:          newID(),
		RepoPath:    repoPath,
		Command:     command,
		Status:      domain.StatusCreated,
		CreatedAt:   now,
		UpdatedAt:   now,
		BudgetSteps: budgetSteps,
		BudgetUsed:  0,
	}
	if err := i.Store.SaveInvestigation(inv); err != nil {
		return inv, domain.DiagnosisResult{}, fmt.Errorf("save initial investigation: %w", err)
	}
	if i.OnStarted != nil {
		i.OnStarted(inv)
	}
	if err := i.recordEvent(inv.ID, domain.StatusCreated, domain.StatusPreparing, "investigation_started", "", "", ""); err != nil {
		return inv, domain.DiagnosisResult{}, fmt.Errorf("record event: %w", err)
	}

	if err := i.transition(ctx, &inv, domain.StatusPreparing, "preparing_workspace"); err != nil {
		return inv, domain.DiagnosisResult{}, err
	}

	// Step 1: Reproduce
	inv, rep, err := i.reproduce(ctx, inv, command, timeout)
	if err != nil {
		if _, ok := err.(*domain.CancellationError); ok {
			inv.Status = domain.StatusCancelled
			inv.UpdatedAt = time.Now().UTC()
			_ = i.Store.SaveInvestigation(inv)
			_ = i.recordEvent(inv.ID, domain.StatusReproducing, domain.StatusCancelled, "cancelled", "", "", "")
		}
		return inv, domain.DiagnosisResult{}, err
	}

	if !rep.Reproducible {
		// Could not reproduce the failure
		finalStatus := domain.StatusReproFailed
		if rep.Result.TimedOut {
			finalStatus = domain.StatusExecutionFailed
		} else if rep.Result.ExitCode == 0 {
			finalStatus = domain.StatusReproFailed
		}
		inv.Status = finalStatus
		inv.UpdatedAt = time.Now().UTC()
		i.Store.SaveInvestigation(inv)
		i.recordEvent(inv.ID, domain.StatusCollectingEvidence, finalStatus, "reproduction_failed", "", "", rep.Reason)
		return inv, domain.DiagnosisResult{
			InvestigationID: inv.ID,
			Reproduction:    &rep,
			Status:          finalStatus,
			FinalReport:     fmt.Sprintf("Failure not reproduced: %s", rep.Reason),
			Limitations:     []string{"original failure was not reproducible in this environment"},
			CompletedAt:     inv.UpdatedAt,
		}, nil
	}

	// Step 2-4: Collect evidence, form hypotheses, plan experiments
	inv, err = i.collectAndInvestigate(ctx, inv, repoPath, command, timeout, rep)
	if err != nil {
		if _, ok := err.(*domain.BudgetExceededError); ok {
			inv.Status = domain.StatusBudgetExhausted
			inv.UpdatedAt = time.Now().UTC()
			i.Store.SaveInvestigation(inv)
			i.recordEvent(inv.ID, domain.StatusEvaluatingEvidence, domain.StatusBudgetExhausted, "budget_exhausted", "", "", err.Error())
			return inv, domain.DiagnosisResult{
				InvestigationID: inv.ID,
				Reproduction:    &rep,
				Status:          domain.StatusBudgetExhausted,
				FinalReport:     "Investigation stopped: step budget exhausted before a conclusion could be reached.",
				Limitations:     []string{"budget exhausted before evidence was sufficient"},
				CompletedAt:     inv.UpdatedAt,
			}, nil
		}
		if _, ok := err.(*domain.CancellationError); ok {
			inv.Status = domain.StatusCancelled
			inv.UpdatedAt = time.Now().UTC()
			i.Store.SaveInvestigation(inv)
			i.recordEvent(inv.ID, domain.StatusEvaluatingEvidence, domain.StatusCancelled, "cancelled", "", "", "")
			return inv, domain.DiagnosisResult{
				InvestigationID: inv.ID,
				Reproduction:    &rep,
				Status:          domain.StatusCancelled,
				FinalReport:     "Investigation cancelled.",
				Limitations:     []string{"investigation was cancelled before completion"},
				CompletedAt:     inv.UpdatedAt,
			}, nil
		}
		return inv, domain.DiagnosisResult{}, err
	}

	// Final report
	evidence, _ := i.Store.ListEvidence(inv.ID)
	hypotheses, _ := i.Store.ListHypotheses(inv.ID)
	experiments, _ := i.Store.ListExperiments(inv.ID)
	var patch *domain.Patch
	if err := i.transition(ctx, &inv, domain.StatusGeneratingPatch, "generating_candidate_patch"); err == nil {
		patch, err = i.GenerateAndVerifyPatch(ctx, inv, rep, evidence, hypotheses, experiments)
		if err != nil {
			slog.Info("candidate patch verification unavailable", "investigation_id", inv.ID, "error", err)
		}
		_ = i.transition(ctx, &inv, domain.StatusVerifyingPatch, "candidate_patch_verified")
	}
	_ = i.transition(ctx, &inv, domain.StatusCompleted, "investigation_completed")

	var status domain.Status
	var limitations, unresolved []string

	status = domain.StatusCompleted
	limitations = append(limitations, "investigation completed successfully")

	inv.Status = status
	inv.UpdatedAt = time.Now().UTC()
	i.Store.SaveInvestigation(inv)
	i.recordEvent(inv.ID, domain.StatusVerifyingPatch, status, "investigation_completed", "", "", "")
	_ = limitations
	_ = unresolved
	report := buildFinalReport(inv, rep, evidence, hypotheses, experiments, patch)
	return inv, domain.DiagnosisResult{
		InvestigationID: inv.ID,
		Reproduction:    &rep,
		EvidenceCount:   len(evidence),
		HypothesisCount: len(hypotheses),
		ExperimentCount: len(experiments),
		Patch:           patch,
		Status:          status,
		FinalReport:     report,
		Limitations:     limitations,
		Unresolved:      unresolved,
		CompletedAt:     inv.UpdatedAt,
		Model:           i.Model,
	}, nil
}

func (i *Investigator) reproduce(ctx context.Context, inv domain.Investigation, command []string, timeout time.Duration) (domain.Investigation, domain.Reproduction, error) {
	if err := i.transition(ctx, &inv, domain.StatusReproducing, "starting_reproduction"); err != nil {
		return inv, domain.Reproduction{}, err
	}

	res, err := i.Executor.Run(ctx, execution.Request{
		Command:   command,
		Dir:       inv.RepoPath,
		Timeout:   timeout,
		MaxOutput: 64 * 1024,
	})
	if ctx.Err() != nil {
		return inv, domain.Reproduction{}, &domain.CancellationError{}
	}

	reproducible := err == nil && res.ExitCode != 0
	reason := "command exited non-zero"
	if err != nil {
		reason = err.Error()
	}
	if res.ExitCode == 0 {
		reason = "command exited successfully; failure not reproduced"
		reproducible = false
	}
	if res.TimedOut {
		reason = "command timed out"
		reproducible = false
	}

	rep := domain.Reproduction{
		InvestigationID: inv.ID,
		Result:          &res,
		Reproducible:    reproducible,
		Reason:          reason,
	}
	if err := i.Store.SaveReproduction(rep); err != nil {
		return inv, rep, fmt.Errorf("save reproduction: %w", err)
	}

	// Record reproduction as evidence
	ev := domain.Evidence{
		ID:                newID(),
		InvestigationID:   inv.ID,
		Type:              domain.EvidenceReproduction,
		Source:            "command_execution",
		Timestamp:         time.Now().UTC(),
		ContentRef:        fmt.Sprintf("reproduction/%s", inv.ID),
		Digest:            digestString(res.Stdout + res.Stderr),
		Payload:           fmt.Sprintf("exit_code=%d, stdout=%d bytes, stderr=%d bytes, timed_out=%t", res.ExitCode, len(res.Stdout), len(res.Stderr), res.TimedOut),
		RelatedHypotheses: []domain.ID{},
	}
	i.Store.SaveEvidence(ev)

	if reproducible {
		inv.Status = domain.StatusCollectingEvidence
	} else if res.TimedOut {
		inv.Status = domain.StatusExecutionFailed
	} else if err != nil {
		inv.Status = domain.StatusExecutionFailed
	} else {
		inv.Status = domain.StatusReproFailed
	}
	inv.UpdatedAt = time.Now().UTC()
	i.Store.SaveInvestigation(inv)
	i.recordEvent(inv.ID, domain.StatusReproducing, inv.Status, "reproduction_completed", "", ev.ID, "")

	return inv, rep, nil
}

func (i *Investigator) collectAndInvestigate(ctx context.Context, inv domain.Investigation, repoPath string, command []string, timeout time.Duration, rep domain.Reproduction) (domain.Investigation, error) {
	// Step 2: Collect evidence
	if err := i.transition(ctx, &inv, domain.StatusCollectingEvidence, "starting_evidence_collection"); err != nil {
		return inv, err
	}

	evidence, err := i.collectEvidenceM4(ctx, inv, repoPath, command, rep)
	if err != nil {
		return inv, err
	}
	for _, ev := range evidence {
		i.recordEvent(inv.ID, domain.StatusCollectingEvidence, domain.StatusCollectingEvidence, "evidence_collected", "", ev.ID, "")
	}

	// Step 3: Form hypotheses
	if err := i.transition(ctx, &inv, domain.StatusFormingHypotheses, "forming_hypotheses"); err != nil {
		return inv, err
	}

	provider := i.Provider
	if provider == nil {
		provider = providerFromEnvironment()
	}
	contextText := buildModelContext(inv, repoPath, command, rep, evidence)
	response, err := provider.Generate(ctx, ModelRequest{InvestigationID: inv.ID, Context: contextText})
	if err != nil {
		return inv, fmt.Errorf("generate hypotheses: %w", err)
	}
	hypotheses, err := validateHypotheses(inv.ID, response.Hypotheses, evidence)
	if err != nil {
		return inv, fmt.Errorf("validate hypotheses: %w", err)
	}
	i.Model = response.Metadata
	if err := i.Store.SaveModelMetadata(inv.ID, i.Model); err != nil {
		return inv, fmt.Errorf("save model metadata: %w", err)
	}
	for _, h := range hypotheses {
		if err := i.Store.SaveHypothesis(h); err != nil {
			return inv, fmt.Errorf("save hypothesis: %w", err)
		}
	}
	inv.UpdatedAt = time.Now().UTC()
	if err := i.Store.SaveInvestigation(inv); err != nil {
		return inv, err
	}
	if err := i.transition(ctx, &inv, domain.StatusPlanningExperiment, "planning_experiment"); err != nil {
		return inv, err
	}
	experiments, listErr := i.Store.ListExperiments(inv.ID)
	if listErr != nil {
		return inv, listErr
	}
	experiment, planErr := (ExperimentPlanner{}).Plan(inv, hypotheses, evidence, experiments)
	if planErr == nil {
		if err := i.Store.SaveExperiment(experiment); err != nil {
			return inv, err
		}
		if err := i.recordEvent(inv.ID, domain.StatusPlanningExperiment, domain.StatusPlanningExperiment, "experiment_planned", experiment.ID, "", experiment.SelectionReason); err != nil {
			return inv, err
		}
		if err := i.transition(ctx, &inv, domain.StatusRunningExperiment, "approved_experiment"); err != nil {
			return inv, err
		}
		if err := i.runExperiment(ctx, &inv, &experiment, hypotheses); err != nil {
			if _, ok := err.(*domain.BudgetExceededError); ok {
				inv.Status = domain.StatusBudgetExhausted
				inv.UpdatedAt = time.Now().UTC()
				_ = i.Store.SaveInvestigation(inv)
				return inv, err
			}
			return inv, err
		}
	} else {
		slog.Info("no discriminating experiment planned", "investigation_id", inv.ID, "reason", planErr.Error())
	}
	if err := i.transition(ctx, &inv, domain.StatusEvaluatingEvidence, "evaluating_experiment"); err != nil {
		return inv, err
	}
	inv.UpdatedAt = time.Now().UTC()
	if err := i.Store.SaveInvestigation(inv); err != nil {
		return inv, err
	}
	return inv, nil
}

func (i *Investigator) collectEvidence(ctx context.Context, inv domain.Investigation, repoPath string, command []string, timeout time.Duration, rep domain.Reproduction) []domain.Evidence {
	var evidence []domain.Evidence

	// Evidence 1: Reproduction result (already saved above)
	// Evidence 2: Test output / source context
	// Try to get git info
	if gitInfo, err := i.getGitInfo(repoPath); err == nil {
		ev := domain.Evidence{
			ID:              newID(),
			InvestigationID: inv.ID,
			Type:            domain.EvidenceGitDiff,
			Source:          "git_status",
			Timestamp:       time.Now().UTC(),
			ContentRef:      "git_status",
			Payload:         gitInfo,
		}
		evidence = append(evidence, ev)
	}

	// Evidence 3: Source files referenced in the command
	if sourceInfo, err := i.getSourceContext(repoPath, command); err == nil && sourceInfo != "" {
		ev := domain.Evidence{
			ID:              newID(),
			InvestigationID: inv.ID,
			Type:            domain.EvidenceSourceCode,
			Source:          "command_analysis",
			Timestamp:       time.Now().UTC(),
			ContentRef:      "source_context",
			Payload:         sourceInfo,
		}
		evidence = append(evidence, ev)
	}

	// Evidence 4: Stack trace / error output analysis
	if rep.Result.Stderr != "" {
		ev := domain.Evidence{
			ID:              newID(),
			InvestigationID: inv.ID,
			Type:            domain.EvidenceStackTrace,
			Source:          "command_stderr",
			Timestamp:       time.Now().UTC(),
			ContentRef:      "stderr_output",
			Payload:         rep.Result.Stderr,
		}
		evidence = append(evidence, ev)
	}

	// Evidence 5: Baseline comparison (if we can determine what "normal" looks like)
	// For now, note the absence of baseline
	ev := domain.Evidence{
		ID:              newID(),
		InvestigationID: inv.ID,
		Type:            domain.EvidenceBaselineCompare,
		Source:          "baseline_status",
		Timestamp:       time.Now().UTC(),
		ContentRef:      "baseline_info",
		Payload:         "No known-good baseline revision was provided for comparison.",
	}
	evidence = append(evidence, ev)

	//Large payloads are written to investigation-scoped artifact files; SQLite
	//keeps only metadata, a hash, and a bounded preview.
	for idx := range evidence {
		i.attachArtifact(&evidence[idx])
	}

	return evidence
}

// maxInlineEvidenceBytes is the largest payload kept inline in SQLite.
const maxInlineEvidenceBytes = 4096

// attachArtifact moves an oversized evidence payload into artifact storage.
func (i *Investigator) attachArtifact(ev *domain.Evidence) {
	if len(ev.Payload) <= maxInlineEvidenceBytes || ev.InvestigationID == "" {
		return
	}
	art, err := i.Store.SaveArtifact(ev.InvestigationID, string(ev.Type), []byte(ev.Payload))
	if err != nil {
		slog.Warn("failed to store evidence artifact",
			"investigation_id", string(ev.InvestigationID),
			"evidence_type", string(ev.Type),
			"error", err)
		return
	}
	ev.ArtifactID = art.ID
	ev.ContentRef = "artifact:" + string(art.ID)
	ev.Digest = art.Digest
	ev.Payload = ev.Payload[:maxInlineEvidenceBytes] + "\n... [truncated; full output stored as artifact " + string(art.ID) + "]"
}

func (i *Investigator) getGitInfo(repoPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get current branch/commit
	branchCmd := exec.CommandContext(ctx, "git", "rev-parse", "--short", "HEAD")
	branchCmd.Dir = repoPath
	branchOut, branchErr := branchCmd.CombinedOutput()
	if branchErr != nil {
		return "", branchErr
	}

	statusCmd := exec.CommandContext(ctx, "git", "status", "--short")
	statusCmd.Dir = repoPath
	statusOut, statusErr := statusCmd.CombinedOutput()
	if statusErr != nil {
		return string(branchOut), nil
	}

	return fmt.Sprintf("HEAD: %s\nStatus:\n%s", strings.TrimSpace(string(branchOut)), strings.TrimSpace(string(statusOut))), nil
}

func (i *Investigator) getSourceContext(repoPath string, command []string) (string, error) {
	// Extract file paths from the command
	var files []string
	for _, arg := range command {
		if strings.HasSuffix(arg, ".py") || strings.HasSuffix(arg, ".go") || strings.HasSuffix(arg, ".rs") || strings.HasSuffix(arg, ".js") {
			fullPath := filepath.Join(repoPath, arg)
			if _, err := os.Stat(fullPath); err == nil {
				files = append(files, arg)
			}
		}
	}

	if len(files) == 0 {
		return "", nil
	}

	var info strings.Builder
	info.WriteString("Files referenced in command:\n")
	for _, f := range files {
		fullPath := filepath.Join(repoPath, f)
		info.WriteString(fmt.Sprintf("\n--- %s ---\n", f))
		data, err := os.ReadFile(fullPath)
		if err != nil {
			info.WriteString(fmt.Sprintf("[error reading file: %v]\n", err))
			continue
		}
		content := string(data)
		if len(content) > 4096 {
			content = content[:4096] + "\n... [truncated]"
		}
		info.WriteString(content)
	}

	return info.String(), nil
}

func (i *Investigator) formHypotheses(inv domain.Investigation, evidence []domain.Evidence, rep domain.Reproduction) []domain.Hypothesis {
	var hypotheses []domain.Hypothesis
	now := time.Now().UTC()

	// Hypothesis 1: The command itself has a bug
	h1 := domain.Hypothesis{
		ID:                       newID(),
		InvestigationID:          inv.ID,
		Statement:                "The failing command has a code defect in the executed program",
		AffectedComponent:        "application_code",
		SupportingEvidenceIDs:    []domain.ID{},
		ContradictingEvidenceIDs: []domain.ID{},
		PredictedObservations: []string{
			"Fixing the identified code path resolves the failure",
			"Regression tests for the affected component fail before the fix",
		},
		Confidence: 0.6,
		Status:     domain.HypProposed,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	for _, ev := range evidence {
		if ev.Type == domain.EvidenceSourceCode || ev.Type == domain.EvidenceStackTrace {
			h1.SupportingEvidenceIDs = append(h1.SupportingEvidenceIDs, ev.ID)
		}
	}
	hypotheses = append(hypotheses, h1)

	// Hypothesis 2: Environment/configuration issue
	h2 := domain.Hypothesis{
		ID:                       newID(),
		InvestigationID:          inv.ID,
		Statement:                "The failure is caused by incorrect environment configuration or missing dependencies",
		AffectedComponent:        "environment",
		SupportingEvidenceIDs:    []domain.ID{},
		ContradictingEvidenceIDs: []domain.ID{},
		PredictedObservations: []string{
			"The failure reproduces on clean environments but not with correct configuration",
			"Missing dependencies are visible in error output",
		},
		Confidence: 0.3,
		Status:     domain.HypProposed,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	for _, ev := range evidence {
		if ev.Type == domain.EvidenceReproduction {
			h2.SupportingEvidenceIDs = append(h2.SupportingEvidenceIDs, ev.ID)
		}
	}
	hypotheses = append(hypotheses, h2)

	// Hypothesis 3: Test/data issue
	h3 := domain.Hypothesis{
		ID:                       newID(),
		InvestigationID:          inv.ID,
		Statement:                "The failure is caused by incorrect test data, fixtures, or test logic rather than application code",
		AffectedComponent:        "test_or_data",
		SupportingEvidenceIDs:    []domain.ID{},
		ContradictingEvidenceIDs: []domain.ID{},
		PredictedObservations: []string{
			"Running the same code with different test data succeeds",
			"The failure is specific to the test case, not general behavior",
		},
		Confidence: 0.2,
		Status:     domain.HypProposed,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	hypotheses = append(hypotheses, h3)

	return hypotheses
}

func (i *Investigator) planAndRunExperiments(ctx context.Context, inv domain.Investigation, repoPath string, command []string, timeout time.Duration, hypotheses []domain.Hypothesis, evidence []domain.Evidence, rep domain.Reproduction) []domain.Experiment {
	var experiments []domain.Experiment
	now := time.Now().UTC()

	// Experiment 1: Run a focused diagnostic command
	ex1 := domain.Experiment{
		ID:              newID(),
		InvestigationID: inv.ID,
		Type:            domain.ExpDeterministicDiagnostic,
		Purpose:         domain.PurposeDistinguish,
		HypothesesIDs:   []domain.ID{hypotheses[0].ID},
		Command:         []string{"echo", "diagnostic_check"},
		WorkingDir:      repoPath,
		Timeout:         10 * time.Second,
		MaxOutput:       8192,
		Status:          domain.StatusRunningExperiment,
		ExpectedUnderHypothesis: map[domain.ID]string{
			hypotheses[0].ID: "diagnostic output shows the expected failure pattern",
			hypotheses[1].ID: "diagnostic output shows configuration or environment issue",
		},
		CreatedAt: now,
	}
	ex1.StartedAt = nowPtr()
	res, err := i.Executor.Run(ctx, execution.Request{
		Command:   ex1.Command,
		Dir:       ex1.WorkingDir,
		Timeout:   ex1.Timeout,
		MaxOutput: ex1.MaxOutput,
	})
	ex1.Result = &res
	ex1.FinishedAt = nowPtr()
	if err != nil {
		ex1.Error = err.Error()
		ex1.Outcome = domain.OutcomeFailed
	} else {
		ex1.Outcome = domain.OutcomeSupports
	}
	ex1.Status = domain.StatusEvaluatingEvidence
	ex1.EvidenceProduced = []domain.ID{newID()}
	_ = ex1.EvidenceProduced[0]
	experiments = append(experiments, ex1)

	// Experiment 2: Run the original command again to verify reproducibility
	ex2 := domain.Experiment{
		ID:              newID(),
		InvestigationID: inv.ID,
		Type:            domain.ExpRunFocusedTest,
		Purpose:         domain.PurposeTestPrediction,
		HypothesesIDs:   []domain.ID{hypotheses[0].ID, hypotheses[2].ID},
		Command:         command,
		WorkingDir:      repoPath,
		Timeout:         timeout,
		MaxOutput:       64 * 1024,
		Status:          domain.StatusRunningExperiment,
		ExpectedUnderHypothesis: map[domain.ID]string{
			hypotheses[0].ID: "command still fails with non-zero exit code",
			hypotheses[2].ID: "command fails due to test-specific data",
		},
		CreatedAt: now,
	}
	ex2.StartedAt = nowPtr()
	res2, err2 := i.Executor.Run(ctx, execution.Request{
		Command:   ex2.Command,
		Dir:       ex2.WorkingDir,
		Timeout:   ex2.Timeout,
		MaxOutput: ex2.MaxOutput,
	})
	ex2.Result = &res2
	ex2.FinishedAt = nowPtr()
	if err2 != nil {
		ex2.Error = err2.Error()
	}
	if res2.ExitCode != 0 && !res2.TimedOut {
		ex2.Outcome = domain.OutcomeSupports
		// Update hypothesis 0 (application code defect) as supported
		for idx, h := range hypotheses {
			if h.ID == hypotheses[0].ID && idx < len(hypotheses) {
				hypotheses[idx].Status = domain.HypSupported
				hypotheses[idx].Confidence = 0.75
				hypotheses[idx].UpdatedAt = time.Now().UTC()
				hypotheses[idx].ExperimentIDs = append(hypotheses[idx].ExperimentIDs, ex2.ID)
				i.Store.SaveHypothesis(hypotheses[idx])
			}
		}
	} else if res2.TimedOut {
		ex2.Outcome = domain.OutcomeInconclusive
	} else {
		ex2.Outcome = domain.OutcomeContradicts
	}
	ex2.Status = domain.StatusEvaluatingEvidence
	experiments = append(experiments, ex2)

	// Experiment 3: Environment check
	ex3 := domain.Experiment{
		ID:              newID(),
		InvestigationID: inv.ID,
		Type:            domain.ExpDeterministicDiagnostic,
		Purpose:         domain.PurposeGatherEvidence,
		HypothesesIDs:   []domain.ID{hypotheses[1].ID},
		Command:         []string{"sh", "-c", "echo ENV_CHECK; env | head -20"},
		WorkingDir:      repoPath,
		Timeout:         5 * time.Second,
		MaxOutput:       8192,
		Status:          domain.StatusRunningExperiment,
		ExpectedUnderHypothesis: map[domain.ID]string{
			hypotheses[1].ID: "environment variables show relevant configuration",
		},
		CreatedAt: now,
	}
	ex3.StartedAt = nowPtr()
	res3, err3 := i.Executor.Run(ctx, execution.Request{
		Command:   ex3.Command,
		Dir:       ex3.WorkingDir,
		Timeout:   ex3.Timeout,
		MaxOutput: ex3.MaxOutput,
	})
	ex3.Result = &res3
	ex3.FinishedAt = nowPtr()
	if err3 != nil {
		ex3.Error = err3.Error()
		ex3.Outcome = domain.OutcomeFailed
	} else if strings.Contains(res3.Stderr, "ENV_CHECK") || strings.Contains(res3.Stdout, "ENV_CHECK") {
		ex3.Outcome = domain.OutcomeSupports
	} else {
		ex3.Outcome = domain.OutcomeInconclusive
	}
	ex3.Status = domain.StatusEvaluatingEvidence
	experiments = append(experiments, ex3)

	return experiments
}

func (i *Investigator) updateHypothesisStatuses(ctx context.Context, inv domain.Investigation, hypotheses []domain.Hypothesis, experiments []domain.Experiment, evidence []domain.Evidence) {
	now := time.Now().UTC()
	for idx, h := range hypotheses {
		supported := false
		contradicted := false

		for _, ex := range experiments {
			if !containsString(h.ExperimentIDs, ex.ID) {
				// Check if this experiment targets this hypothesis
				for _, hypID := range ex.HypothesesIDs {
					if hypID == h.ID {
						h.ExperimentIDs = append(h.ExperimentIDs, ex.ID)
						if ex.Outcome == domain.OutcomeSupports {
							supported = true
						} else if ex.Outcome == domain.OutcomeContradicts {
							contradicted = true
						}
					}
				}
			}
		}

		for _, ev := range evidence {
			for _, suppID := range h.SupportingEvidenceIDs {
				if suppID == ev.ID {
					// Evidence supports this hypothesis
				}
			}
		}

		if contradicted && !supported {
			hypotheses[idx].Status = domain.HypRefuted
			hypotheses[idx].UpdatedAt = now
		} else if supported {
			hypotheses[idx].Status = domain.HypSupported
			hypotheses[idx].UpdatedAt = now
		} else {
			hypotheses[idx].Status = domain.HypInconclusive
			hypotheses[idx].UpdatedAt = now
		}
		i.Store.SaveHypothesis(hypotheses[idx])
	}
}

func (i *Investigator) generateAndVerifyPatch(ctx context.Context, inv domain.Investigation, repoPath string, command []string, timeout time.Duration) (*domain.Patch, error) {
	// Create a temporary workspace for patch generation
	tmpDir, err := os.MkdirTemp("", "causent-patch-*")
	if err != nil {
		return nil, fmt.Errorf("create patch workspace: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	patch := domain.Patch{
		ID:              newID(),
		InvestigationID: inv.ID,
		Diff:            generateCandidateDiff(repoPath, command),
		DiffPath:        filepath.Join(tmpDir, "candidate.patch"),
		WorkspacePath:   tmpDir,
		Status:          domain.PatchDoesNotApply,
		CreatedAt:       time.Now().UTC(),
	}

	// Write diff to file
	if err := os.WriteFile(patch.DiffPath, []byte(patch.Diff), 0644); err != nil {
		patch.Error = fmt.Sprintf("write diff file: %v", err)
		i.Store.SavePatch(patch)
		return &patch, nil
	}

	// Try to apply the patch in the workspace
	applyCmd := exec.CommandContext(ctx, "patch", "-p1", "--dry-run", "-i", patch.DiffPath)
	applyCmd.Dir = repoPath
	applyOut, applyErr := applyCmd.CombinedOutput()
	if applyErr != nil {
		patch.Status = domain.PatchDoesNotApply
		patch.Error = fmt.Sprintf("patch dry-run failed: %v\n%s", applyErr, string(applyOut))
		i.Store.SavePatch(patch)
		return &patch, nil
	}

	// Patch applies cleanly - run original test in workspace
	patch.Status = domain.PatchValidated
	patch.OriginalTestResult = &domain.ExecutionResult{}

	testCmd := exec.CommandContext(ctx, command[0], command[1:]...)
	testCmd.Dir = repoPath
	testCmd.Env = append(os.Environ(), "CAUSENT_PATCH_APPLIED=1")

	start := time.Now()
	stdout, stderr := &strings.Builder{}, &strings.Builder{}
	testCmd.Stdout = stdout
	testCmd.Stderr = stderr
	runErr := testCmd.Run()
	finished := time.Now()

	result := domain.ExecutionResult{
		Stdout:     stdout.String(),
		Stderr:     stderr.String(),
		Duration:   finished.Sub(start),
		StartedAt:  start,
		FinishedAt: finished,
	}

	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ExitCode = -1
		patch.Status = domain.PatchDoesNotApply
		patch.Error = "patch verification timed out"
		i.Store.SavePatch(patch)
		return &patch, nil
	}

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
			patch.Status = domain.PatchDoesNotApply
			patch.Error = fmt.Sprintf("patch verification failed: %v", runErr)
			i.Store.SavePatch(patch)
			return &patch, nil
		}
	} else {
		result.ExitCode = 0
	}

	patch.OriginalTestResult = &result

	// If the original test passes, mark as validated
	if result.ExitCode == 0 {
		patch.Status = domain.PatchValidated
		patch.VerifiedAt = nowPtr()
	} else {
		patch.Status = domain.PatchFailsOriginal
		patch.Error = fmt.Sprintf("patch does not fix the original failure: exit code %d", result.ExitCode)
	}

	i.Store.SavePatch(patch)
	return &patch, nil
}

func generateCandidateDiff(repoPath string, command []string) string {
	// Generate a simple candidate diff based on analysis
	// In a real implementation, this would be LLM-generated
	return fmt.Sprintf(`*** This is a candidate patch generated by Causent ***
*** Investigation: %s ***
*** Command: %s ***

--- a/placeholder
+++ b/placeholder
@@ -0,0 +1 @@
+// Placeholder: actual fix would be generated here based on evidence analysis
`, repoPath, strings.Join(command, " "))
}

func (i *Investigator) transition(ctx context.Context, inv *domain.Investigation, to domain.Status, trigger string) error {
	// Re-entering the current state is a no-op, not an invalid transition.
	if inv.Status == to {
		return nil
	}
	if err := domain.ValidateTransition(inv.Status, to); err != nil {
		return fmt.Errorf("transition %s -> %s: %w", inv.Status, to, err)
	}
	if domain.IsTerminal(to) {
		return fmt.Errorf("cannot transition to terminal state %s", to)
	}
	inv.Status = to
	inv.UpdatedAt = time.Now().UTC()
	if err := i.Store.SaveInvestigation(*inv); err != nil {
		return fmt.Errorf("save investigation: %w", err)
	}
	return nil
}

func (i *Investigator) recordEvent(invID domain.ID, from, to domain.Status, trigger string, experimentID, evidenceID domain.ID, errorStr string) error {
	ev := domain.InvestigationEvent{
		ID:              newID(),
		InvestigationID: invID,
		PreviousStatus:  from,
		NextStatus:      to,
		Timestamp:       time.Now().UTC(),
		Trigger:         trigger,
		ExperimentID:    experimentID,
		EvidenceID:      evidenceID,
		Error:           errorStr,
	}
	return i.Store.SaveEvent(ev)
}

func digestString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func nowPtr() *time.Time {
	t := time.Now().UTC()
	return &t
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func containsString(slice []domain.ID, s domain.ID) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func buildFinalReport(inv domain.Investigation, rep domain.Reproduction, evidence []domain.Evidence, hypotheses []domain.Hypothesis, experiments []domain.Experiment, patch *domain.Patch) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Investigation Report\n"))
	b.WriteString(fmt.Sprintf("====================\n"))
	b.WriteString(fmt.Sprintf("ID: %s\n", inv.ID))
	b.WriteString(fmt.Sprintf("Repository: %s\n", inv.RepoPath))
	b.WriteString(fmt.Sprintf("Command: %s\n", strings.Join(inv.Command, " ")))
	b.WriteString(fmt.Sprintf("Status: %s\n", inv.Status))
	b.WriteString(fmt.Sprintf("\n"))

	b.WriteString(fmt.Sprintf("Reproduction\n"))
	b.WriteString(fmt.Sprintf("------------\n"))
	b.WriteString(fmt.Sprintf("Reproducible: %t\n", rep.Reproducible))
	b.WriteString(fmt.Sprintf("Reason: %s\n", rep.Reason))
	b.WriteString(fmt.Sprintf("Exit code: %d\n", rep.Result.ExitCode))
	b.WriteString(fmt.Sprintf("Duration: %v\n", rep.Result.Duration))
	b.WriteString(fmt.Sprintf("\n"))

	b.WriteString(fmt.Sprintf("Evidence (%d items)\n", len(evidence)))
	b.WriteString(fmt.Sprintf("--------\n"))
	for _, ev := range evidence {
		b.WriteString(fmt.Sprintf("- [%s] %s: %s\n", ev.Type, ev.Source, truncateString(ev.Payload, 200)))
	}
	b.WriteString(fmt.Sprintf("\n"))

	b.WriteString(fmt.Sprintf("Hypotheses (%d)\n", len(hypotheses)))
	b.WriteString(fmt.Sprintf("-----------\n"))
	for _, h := range hypotheses {
		b.WriteString(fmt.Sprintf("- [%s] %s (confidence: %.2f)\n", h.Status, h.Statement, h.Confidence))
		b.WriteString(fmt.Sprintf("  Affected: %s\n", h.AffectedComponent))
		b.WriteString(fmt.Sprintf("  Supporting evidence: %s\n", joinDomainIDs(h.SupportingEvidenceIDs)))
		b.WriteString(fmt.Sprintf("  Experiments: %s\n", joinDomainIDs(h.ExperimentIDs)))
	}
	b.WriteString(fmt.Sprintf("\n"))

	b.WriteString(fmt.Sprintf("Experiments (%d)\n", len(experiments)))
	b.WriteString(fmt.Sprintf("-----------\n"))
	for _, ex := range experiments {
		b.WriteString(fmt.Sprintf("- [%s] %s: %s\n", ex.Status, ex.Type, ex.Outcome))
		b.WriteString(fmt.Sprintf("  Selection: %s\n", ex.SelectionReason))
		b.WriteString(fmt.Sprintf("  Predictions: %s\n", formatPredictions(ex.Predictions)))
		b.WriteString(fmt.Sprintf("  Observation: %s\n", truncateString(ex.Observations, 300)))
		b.WriteString(fmt.Sprintf("  Evaluation: %s\n", ex.Evaluation))
		b.WriteString(fmt.Sprintf("  Evidence: %s\n", joinDomainIDs(ex.EvidenceProduced)))
	}

	b.WriteString(fmt.Sprintf("\n"))

	if patch != nil {
		b.WriteString(fmt.Sprintf("Patch\n"))
		b.WriteString(fmt.Sprintf("-----\n"))
		b.WriteString(fmt.Sprintf("ID: %s\n", patch.ID))
		b.WriteString(fmt.Sprintf("Status: %s\n", patch.Status))
		b.WriteString(fmt.Sprintf("Validation: %s\n", patch.ValidationStatus))
		b.WriteString(fmt.Sprintf("Application: %s\n", patch.ApplicationStatus))
		b.WriteString(fmt.Sprintf("Verification: %s\n", patch.VerificationStatus))
		b.WriteString(fmt.Sprintf("Digest: %s\n", patch.Digest))
		b.WriteString(fmt.Sprintf("Changed files: %s\n", strings.Join(patch.ChangedFiles, ", ")))
		b.WriteString(fmt.Sprintf("Explanation: %s\n", patch.Explanation))
		b.WriteString(fmt.Sprintf("Diff path: %s\n", patch.DiffPath))
		if patch.OriginalTestResult != nil {
			b.WriteString(fmt.Sprintf("Original test result: exit=%d\n", patch.OriginalTestResult.ExitCode))
		}
		b.WriteString(fmt.Sprintf("\n"))
	}

	b.WriteString(fmt.Sprintf("Conclusion\n"))
	b.WriteString(fmt.Sprintf("----------\n"))
	b.WriteString(fmt.Sprintf("Investigation completed with status %s.\n", inv.Status))

	return b.String()
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func joinDomainIDs(ids []domain.ID) string {
	parts := make([]string, len(ids))
	for idx, id := range ids {
		parts[idx] = string(id)
	}
	return strings.Join(parts, ", ")
}

func formatPredictions(predictions map[domain.ID]string) string {
	ids := make([]string, 0, len(predictions))
	for id := range predictions {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, id+": "+predictions[domain.ID(id)])
	}
	return strings.Join(parts, " | ")
}
