package engine

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yashbhu/Hades/internal/domain"
	"github.com/Yashbhu/Hades/internal/persistence"
)

type experimentExecutor struct {
	result domain.ExecutionResult
	err    error
}

func (e experimentExecutor) Run(context.Context, domain.ExecutionRequest) (domain.ExecutionResult, error) {
	return e.result, e.err
}

func TestPlannerSelectsBoundedDiscriminatingProbe(t *testing.T) {
	inv := domain.Investigation{ID: "inv", RepoPath: "/repo", Command: []string{"python3", "test_failure.py"}, BudgetSteps: 3}
	hypotheses := []domain.Hypothesis{
		{ID: "code", AffectedComponent: "application_code", PredictedObservations: []string{"source"}},
		{ID: "fixture", AffectedComponent: "fixture", PredictedObservations: []string{"fixture"}},
	}
	evidence := []domain.Evidence{{ID: "trace", InvestigationID: inv.ID, Type: domain.EvidenceStackTrace, Payload: `File "/repo/test_failure.py", line 4, in test_case`}}
	ex, err := (ExperimentPlanner{}).Plan(inv, hypotheses, evidence, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ex.State != domain.ExperimentPlanned || len(ex.HypothesesIDs) != 2 || len(ex.Predictions) != 2 {
		t.Fatalf("invalid planned experiment: %+v", ex)
	}
	if ex.Command[0] != "python3" || strings.Contains(strings.Join(ex.Command, " "), "sh -c") {
		t.Fatalf("unsafe command: %v", ex.Command)
	}
	if err := validateExperiment(inv, ex); err != nil {
		t.Fatal(err)
	}
}

func TestExperimentExecutionPersistsObservationAndHypothesisHistory(t *testing.T) {
	store, err := persistence.Open(filepath.Join(t.TempDir(), "m5.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	inv := domain.Investigation{ID: "inv", RepoPath: "/repo", Status: domain.StatusRunningExperiment, BudgetSteps: 2, CreatedAt: now, UpdatedAt: now}
	if err := store.SaveInvestigation(inv); err != nil {
		t.Fatal(err)
	}
	hypotheses := []domain.Hypothesis{
		{ID: "code", InvestigationID: inv.ID, Statement: "code", AffectedComponent: "application_code", Confidence: .5, Status: domain.HypProposed, CreatedAt: now, UpdatedAt: now},
		{ID: "fixture", InvestigationID: inv.ID, Statement: "fixture", AffectedComponent: "fixture", Confidence: .3, Status: domain.HypProposed, CreatedAt: now, UpdatedAt: now},
	}
	for _, h := range hypotheses {
		if err := store.SaveHypothesis(h); err != nil {
			t.Fatal(err)
		}
	}
	ex := domain.Experiment{
		ID: "experiment", InvestigationID: inv.ID, State: domain.ExperimentPlanned,
		Type: domain.ExpDeterministicDiagnostic, Purpose: domain.PurposeDistinguish,
		HypothesesIDs: []domain.ID{"code", "fixture"}, Predictions: map[domain.ID]string{
			"code": "SOURCE_CONTEXT_PRESENT", "fixture": "FIXTURE_CONTEXT_PRESENT",
		},
		Command: []string{"python3", "-c", "read-only"}, WorkingDir: "/repo",
		Timeout: time.Second, MaxOutput: 1024, Status: domain.StatusPlanningExperiment,
		CreatedAt: now,
	}
	if err := store.SaveExperiment(ex); err != nil {
		t.Fatal(err)
	}
	investigator := &Investigator{Store: store, Executor: experimentExecutor{result: domain.ExecutionResult{ExitCode: 0, Stdout: "SOURCE_CONTEXT_PRESENT\n", StartedAt: now, FinishedAt: now}}}
	if err := investigator.runExperiment(context.Background(), &inv, &ex, hypotheses); err != nil {
		t.Fatal(err)
	}
	if ex.State != domain.ExperimentCompleted || ex.Outcome != domain.OutcomeSupports || len(ex.EvidenceProduced) != 1 {
		t.Fatalf("unexpected experiment result: %+v", ex)
	}
	observations, err := store.ListEvidence(inv.ID)
	if err != nil || len(observations) != 1 {
		t.Fatalf("experiment evidence not persisted: %d, %v", len(observations), err)
	}
	updated, err := store.ListHypotheses(inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated[0].Status != domain.HypSupported || updated[1].Status != domain.HypInconclusive {
		t.Fatalf("unexpected hypothesis statuses: %+v", updated)
	}
	history, err := store.ListHypothesisHistory("code")
	if err != nil || len(history) != 1 {
		t.Fatalf("hypothesis history not persisted: %d, %v", len(history), err)
	}
}

func TestExecutionFailureDoesNotRefuteHypothesis(t *testing.T) {
	ex := domain.Experiment{Predictions: map[domain.ID]string{"h": "SOURCE_CONTEXT_PRESENT"}, HypothesesIDs: []domain.ID{"h"}, State: domain.ExperimentFailed}
	outcome, evaluation := evaluateExperiment(ex, []domain.Hypothesis{{ID: "h"}})
	if outcome != domain.OutcomeInconclusive || evaluation == "" {
		t.Fatalf("execution failure should remain inconclusive: %s %s", outcome, evaluation)
	}
}

func TestRecoveryMarksRunningExperimentFailedWithoutRerun(t *testing.T) {
	store, err := persistence.Open(filepath.Join(t.TempDir(), "recovery.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	inv := domain.Investigation{ID: "recovery-inv", RepoPath: "/repo", Status: domain.StatusRunningExperiment, CreatedAt: now, UpdatedAt: now}
	if err := store.SaveInvestigation(inv); err != nil {
		t.Fatal(err)
	}
	ex := domain.Experiment{ID: "running", InvestigationID: inv.ID, State: domain.ExperimentRunning, Status: domain.StatusRunningExperiment, CreatedAt: now}
	if err := store.SaveExperiment(ex); err != nil {
		t.Fatal(err)
	}
	investigator := &Investigator{Store: store}
	if _, err := investigator.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.GetExperiment(ex.ID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != domain.ExperimentFailed || !strings.Contains(recovered.Error, "not re-run") {
		t.Fatalf("unexpected recovery result: %+v", recovered)
	}
	second, err := investigator.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Recovered) != 0 {
		t.Fatalf("recovery was not idempotent: %+v", second)
	}
}
