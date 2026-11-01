package engine

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/causent/causent/internal/domain"
	"github.com/causent/causent/internal/persistence"
)

func TestRecoverRepairsInterruptedInvestigationWithoutReplayingCommands(t *testing.T) {
	store, err := persistence.Open(filepath.Join(t.TempDir(), "recover.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	inv := domain.Investigation{
		ID:          domain.NewID(),
		RepoPath:    "/repo",
		Command:     []string{"go", "test", "./..."},
		Status:      domain.StatusRunningExperiment,
		CreatedAt:   now,
		UpdatedAt:   now,
		BudgetSteps: 20,
		BudgetUsed:  3,
	}
	if err := store.SaveInvestigation(inv); err != nil {
		t.Fatalf("save investigation: %v", err)
	}

	started := now
	interrupted := domain.Experiment{
		ID:              domain.NewID(),
		InvestigationID: inv.ID,
		Type:            domain.ExpRunFocusedTest,
		Purpose:         domain.PurposeTestPrediction,
		Command:         []string{"go", "test", "./..."},
		WorkingDir:      "/repo",
		Timeout:         30 * time.Second,
		MaxOutput:       4096,
		Status:          domain.StatusRunningExperiment,
		CreatedAt:       now,
		StartedAt:       &started,
	}
	finishedExperiment := domain.Experiment{
		ID:              domain.NewID(),
		InvestigationID: inv.ID,
		Type:            domain.ExpDeterministicDiagnostic,
		Purpose:         domain.PurposeGatherEvidence,
		Command:         []string{"echo", "ok"},
		WorkingDir:      "/repo",
		Timeout:         5 * time.Second,
		MaxOutput:       1024,
		Status:          domain.StatusEvaluatingEvidence,
		Outcome:         domain.OutcomeSupports,
		CreatedAt:       now,
	}
	for _, ex := range []domain.Experiment{interrupted, finishedExperiment} {
		if err := store.SaveExperiment(ex); err != nil {
			t.Fatalf("save experiment: %v", err)
		}
	}

	event := domain.InvestigationEvent{
		ID:              domain.NewID(),
		InvestigationID: inv.ID,
		PreviousStatus:  domain.StatusPlanningExperiment,
		NextStatus:      domain.StatusRunningExperiment,
		Timestamp:       now,
		Trigger:         "running_experiment",
	}
	if err := store.SaveEvent(event); err != nil {
		t.Fatalf("save event: %v", err)
	}

	investigator := &Investigator{Store: store}
	report, err := investigator.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if report.Found != 1 || len(report.Recovered) != 1 {
		t.Fatalf("expected 1 recovered investigation, got found=%d recovered=%d", report.Found, len(report.Recovered))
	}
	if report.Recovered[0].InterruptedRun != 1 {
		t.Fatalf("expected 1 interrupted experiment, got %d", report.Recovered[0].InterruptedRun)
	}
	if len(report.Recovered[0].InterruptedIDs) != 1 || report.Recovered[0].InterruptedIDs[0] != interrupted.ID {
		t.Fatalf("unexpected interrupted ids: %v", report.Recovered[0].InterruptedIDs)
	}

	repaired, err := store.GetInvestigation(inv.ID)
	if err != nil {
		t.Fatalf("get investigation: %v", err)
	}
	if repaired.Status != domain.StatusInconclusive {
		t.Fatalf("status = %s, want %s", repaired.Status, domain.StatusInconclusive)
	}
	if repaired.BudgetUsed != inv.BudgetUsed {
		t.Fatalf("budget history lost: %d", repaired.BudgetUsed)
	}

	gotInterrupted, err := store.GetExperiment(interrupted.ID)
	if err != nil {
		t.Fatalf("get interrupted experiment: %v", err)
	}
	if !strings.Contains(gotInterrupted.Error, "interrupted") {
		t.Fatalf("expected interruption note, got %q", gotInterrupted.Error)
	}
	if gotInterrupted.Outcome != domain.OutcomeFailed {
		t.Fatalf("outcome = %s, want %s", gotInterrupted.Outcome, domain.OutcomeFailed)
	}
	if gotInterrupted.FinishedAt == nil {
		t.Fatal("expected finished_at to be recorded for the interrupted experiment")
	}

	gotFinished, err := store.GetExperiment(finishedExperiment.ID)
	if err != nil {
		t.Fatalf("get finished experiment: %v", err)
	}
	if gotFinished.Outcome != domain.OutcomeSupports || gotFinished.Error != "" {
		t.Fatalf("completed experiment was modified: %+v", gotFinished)
	}

	events, err := store.ListEvents(inv.ID)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected original event plus recovery event, got %d", len(events))
	}
	var sawRecovery bool
	for _, ev := range events {
		if ev.Trigger == "recovered_after_restart" {
			sawRecovery = true
			if ev.PreviousStatus != domain.StatusRunningExperiment || ev.NextStatus != domain.StatusInconclusive {
				t.Fatalf("recovery event status mismatch: %s -> %s", ev.PreviousStatus, ev.NextStatus)
			}
		}
	}
	if !sawRecovery {
		t.Fatal("expected a recovered_after_restart event")
	}

	// Recovery must be idempotent: a second pass finds nothing to repair.
	second, err := investigator.Recover(context.Background())
	if err != nil {
		t.Fatalf("second recover: %v", err)
	}
	if second.Found != 0 || len(second.Recovered) != 0 {
		t.Fatalf("expected no work on second pass, got found=%d recovered=%d", second.Found, len(second.Recovered))
	}
}

func TestRecoverLeavesCompletedInvestigationsAlone(t *testing.T) {
	store, err := persistence.Open(filepath.Join(t.TempDir(), "recover-complete.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	inv := domain.Investigation{
		ID:        domain.NewID(),
		RepoPath:  "/repo",
		Command:   []string{"go", "test"},
		Status:    domain.StatusCompleted,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.SaveInvestigation(inv); err != nil {
		t.Fatalf("save: %v", err)
	}

	report, err := (&Investigator{Store: store}).Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if report.Found != 0 {
		t.Fatalf("expected no incomplete investigations, got %d", report.Found)
	}
}
