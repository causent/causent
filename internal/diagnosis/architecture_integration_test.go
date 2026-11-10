package diagnosis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/persistence"
)

func TestEvidenceFirstContinuesIntoAdaptiveController(t *testing.T) {
	dir := newRepo(t)
	cacherPath := "staging/src/k8s.io/apiserver/pkg/storage/cacher/cacher.go"
	setupPath := "staging/src/k8s.io/apiserver/pkg/storage/cacher/testing/setup/setup.go"
	cacher := "package cacher\n\ntype Cacher struct{}\nfunc (c *Cacher) startBackgroundResync() {}\nfunc (c *Cacher) Stop() {}\nfunc NewCacherFromConfig() *Cacher {\n\tcacher := &Cacher{}\n" + strings.Repeat("\t// context\n", 489) + "\tgo cacher.startBackgroundResync()\n\treturn cacher\n}\n"
	setup := "package setup\n\ntype raw struct{}\nfunc (raw) Stop() {}\nfunc SetupWithCacher() {\n\trawCacher := raw{}\n" + strings.Repeat("\t// context\n", 180) + "\trawCacher.Stop()\n}\n"
	commit(t, dir, "kubernetes race source", map[string]string{cacherPath: cacher, setupPath: setup})
	logData, err := os.ReadFile("testdata/kubernetes-race.log")
	if err != nil {
		t.Fatal(err)
	}
	evidence := ParseCITextEvidence(string(logData), EvidenceProvenance{Provider: "fixture"})
	store, err := persistence.Open(filepath.Join(t.TempDir(), "adaptive-evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	report, err := DiagnoseEvidence(context.Background(), Config{RepoPath: dir, Command: []string{"go", "test", "-race"}, Store: store, AdaptiveMaxIterations: 2, AdaptiveMaxActivities: 2, AdaptiveMaxExperiments: 1}, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if report.StoppingReason == "execution_unavailable" || report.AdaptiveIterations == 0 {
		t.Fatalf("evidence-first controller did not execute adaptive work: stopping=%q iterations=%d objective=%#v actions=%#v", report.StoppingReason, report.AdaptiveIterations, report.InvestigationObjective, report.InvestigationActions)
	}
	if report.InvestigationObjective == nil || report.InvestigationObjective.Status == "investigating" {
		t.Fatalf("adaptive controller left an invalid terminal objective: %#v", report.InvestigationObjective)
	}
	if report.RootCause.Status == "confirmed" {
		t.Fatalf("fixture did not justify a causal conclusion: %#v", report.RootCause)
	}
	stopInspected := false
	for _, item := range report.Evidence {
		if item.Kind == "source related function" && strings.Contains(item.Detail, "func (raw) Stop") {
			stopInspected = true
		}
	}
	if !stopInspected {
		t.Fatalf("cleanup implementation was not followed: %#v", report.InvestigationActions)
	}
	activities, err := store.ListActivities(domain.ID(report.InvestigationID))
	if err != nil {
		t.Fatal(err)
	}
	if len(activities) == 0 {
		t.Fatal("adaptive action was not persisted")
	}
	adaptivePersisted := false
	for _, activity := range activities {
		if strings.Contains(string(activity.ID), ":adaptive:") && activity.SelectionReason != "" {
			adaptivePersisted = true
		}
	}
	if !adaptivePersisted {
		t.Fatalf("persisted activities did not include an adaptive selection: %#v", activities)
	}
	if report.TerminalInvestigation == nil || report.TerminalInvestigation.Reason == "" {
		t.Fatalf("terminal explanation was not published: %#v", report.TerminalInvestigation)
	}
	if report.TerminalInvestigation.Reason != report.StoppingReason {
		t.Fatalf("terminal reason mismatch: report=%q explanation=%q", report.StoppingReason, report.TerminalInvestigation.Reason)
	}
	if len(report.TerminalInvestigation.UnresolvedDependencies) == 0 {
		t.Fatalf("fixture should retain unresolved dependencies: %#v", report.TerminalInvestigation)
	}
	checkpoint, err := store.GetAdaptiveState(domain.ID(report.InvestigationID))
	if err != nil {
		t.Fatal(err)
	}
	if checkpoint.TerminalExplanation == nil || checkpoint.TerminalExplanation.Reason != report.StoppingReason {
		t.Fatalf("terminal explanation was not durably checkpointed: %#v", checkpoint.TerminalExplanation)
	}
	if checkpoint.TerminalExplanation.Budget.MaxIterations == 0 || checkpoint.TerminalExplanation.Budget.IterationsUsed == 0 {
		t.Fatalf("adaptive budget was overwritten in terminal explanation: %#v", checkpoint.TerminalExplanation.Budget)
	}
	for _, action := range report.InvestigationActions {
		if strings.Contains(action.ID, ":adaptive:") && action.Target == "" {
			t.Fatalf("adaptive action lost target provenance: %#v", action)
		}
	}
}

func TestDiagnosisPersistsRepositoryGraphAndLocalization(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "failing source", map[string]string{
		"main.go": "package main\nfunc Broken() { panic(\"boom\") }\n",
		"run.sh":  "#!/bin/sh\necho 'panic at main.go:2' >&2\nexit 1\n",
	})
	store, err := persistence.Open(filepath.Join(t.TempDir(), "architecture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	report, err := Run(context.Background(), Config{RepoPath: dir, Command: []string{"sh", "run.sh"}, Attempts: 2, Timeout: 30 * time.Second, Executor: testExecutor(t), Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Candidates) == 0 {
		t.Fatalf("expected candidates, uncertainty=%v", report.Uncertainty)
	}
	if len(report.Hypotheses) == 0 || len(report.Findings) == 0 || len(report.FailureGroups) == 0 {
		t.Fatalf("reasoning state missing: hypotheses=%d findings=%d groups=%d", len(report.Hypotheses), len(report.Findings), len(report.FailureGroups))
	}
	if len(report.Experiments) < 1 || report.AdaptiveIterations < 2 || report.StoppingReason == "" {
		t.Fatalf("adaptive state missing: experiments=%d iterations=%d stop=%q hypotheses=%#v questions=%#v uncertainty=%v", len(report.Experiments), report.AdaptiveIterations, report.StoppingReason, report.Hypotheses, report.UnresolvedQuestions, report.Uncertainty)
	}
	if report.InvestigationObjective != nil && report.InvestigationObjective.Status == "investigating" {
		t.Fatalf("completed controller left objective investigating: %#v stopping=%q", report.InvestigationObjective, report.StoppingReason)
	}
	if report.Metrics == nil || report.Metrics.InvestigationActions != len(report.InvestigationActions) {
		t.Fatalf("metrics/action ledger mismatch: metrics=%+v actions=%d", report.Metrics, len(report.InvestigationActions))
	}
	activities, err := store.ListActivities(domain.ID(report.InvestigationID))
	if err != nil {
		t.Fatal(err)
	}
	var selected bool
	seenAdaptiveTypes := map[string]bool{}
	for _, activity := range activities {
		if activity.Type == "RerunFailingTest" && activity.SelectionReason != "" {
			selected = true
		}
		if activity.SelectionReason != "" {
			seenAdaptiveTypes[activity.Type] = true
		}
	}
	if !selected {
		t.Fatalf("adaptive selection rationale not persisted: %#v", activities)
	}
	if len(seenAdaptiveTypes) < 1 {
		t.Fatalf("expected at least one adaptive action type, got %#v", seenAdaptiveTypes)
	}
	adaptive, err := store.GetAdaptiveState(domain.ID(report.InvestigationID))
	if err != nil || adaptive.StoppingReason == "" {
		t.Fatalf("adaptive checkpoint missing: %#v %v", adaptive, err)
	}
	var nodes, failures int
	if err := store.ListArchitecture("program_node", "", func(data []byte) error { nodes++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := store.ListArchitecture("failure_episode", "", func(data []byte) error { failures++; return nil }); err != nil {
		t.Fatal(err)
	}
	if nodes == 0 || failures == 0 {
		t.Fatalf("persisted nodes=%d failures=%d", nodes, failures)
	}
	rels, err := store.ListRelationships(domain.ID(report.InvestigationID))
	if err != nil {
		t.Fatal(err)
	}
	foundManifest := false
	for _, rel := range rels {
		if rel.Type == "MANIFESTED_AT" {
			foundManifest = true
		}
	}
	if !foundManifest {
		t.Fatalf("no manifested-at relationship in %#v", rels)
	}
	activities, err = store.ListActivities(domain.ID(report.InvestigationID))
	if err != nil {
		t.Fatal(err)
	}
	if len(activities) < 3 {
		t.Fatalf("activities=%d", len(activities))
	}
}

func TestAdaptiveComparisonUsesBaseAndHeadEvidence(t *testing.T) {
	dir := newRepo(t)
	good := commit(t, dir, "good", map[string]string{"main.go": "package main\nfunc Broken() {}\n", "run.sh": "#!/bin/sh\nexit 0\n"})
	commit(t, dir, "bad", map[string]string{"run.sh": "#!/bin/sh\necho 'panic at main.go:2' >&2\nexit 1\n"})
	store, err := persistence.Open(filepath.Join(t.TempDir(), "comparison.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	report, err := Run(context.Background(), Config{RepoPath: dir, BaseRef: good, Command: []string{"sh", "run.sh"}, Attempts: 1, Timeout: 30 * time.Second, Executor: testExecutor(t), Store: store, AdaptiveMaxIterations: 3, AdaptiveMaxActivities: 3, AdaptiveMaxExperiments: 2})
	if err != nil {
		t.Fatal(err)
	}
	activities, err := store.ListActivities(domain.ID(report.InvestigationID))
	if err != nil {
		t.Fatal(err)
	}
	var compared bool
	for _, activity := range activities {
		if activity.Type == "CompareRevisions" {
			compared = true
		}
	}
	if !compared {
		t.Fatalf("comparison action was not selected: %#v", activities)
	}
	var found bool
	for _, experiment := range report.Experiments {
		if experiment.EvidenceProduced != nil {
			found = true
		}
	}
	if !found {
		t.Fatalf("comparison experiment evidence missing: %#v", report.Experiments)
	}
}

func TestDiagnosisExtractsMultipleFailuresFromOneCIExecution(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "multiple failures", map[string]string{
		"main.go": "package main\nfunc Broken() { panic(\"boom\") }\n",
		"run.sh":  "#!/bin/sh\necho '--- FAIL: TestOne (0.01s)' >&2\necho '--- FAIL: TestTwo (0.01s)' >&2\necho 'panic at main.go:2' >&2\nexit 1\n",
	})
	store, err := persistence.Open(filepath.Join(t.TempDir(), "multiple.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	report, err := Run(context.Background(), Config{RepoPath: dir, Command: []string{"sh", "run.sh"}, Attempts: 1, Timeout: 30 * time.Second, Executor: testExecutor(t), Store: store, AdaptiveMaxIterations: 2, AdaptiveMaxActivities: 2, AdaptiveMaxExperiments: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.FailureGroups) == 0 {
		t.Fatalf("failure groups missing: %#v", report)
	}
	episodes := report.FailureEpisodes
	if len(episodes) < 2 {
		t.Fatalf("expected separate episodes, got %#v parsed=%#v baseline=%#v", episodes, parseFailureObservations(report.Baseline.Results[0].Stderr), report.Baseline.Results)
	}
	seen := map[string]bool{}
	for _, episode := range episodes {
		seen[episode.TestIdentifier] = true
	}
	if !seen["TestOne"] || !seen["TestTwo"] {
		t.Fatalf("test identifiers missing: %#v", episodes)
	}
}
