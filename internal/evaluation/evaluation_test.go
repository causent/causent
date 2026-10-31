package evaluation

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yashbhu/Hades/internal/domain"
	"github.com/Yashbhu/Hades/internal/engine"
	"github.com/Yashbhu/Hades/internal/execution"
	"github.com/Yashbhu/Hades/internal/persistence"
)

type fakeProvider struct{ diff string }

func (fakeProvider) Generate(_ context.Context, request engine.ModelRequest) (engine.ModelResponse, error) {
	var ids []string
	for _, line := range strings.Split(request.Context, "\n") {
		if strings.HasPrefix(line, "EVIDENCE ") {
			ids = append(ids, strings.Fields(line)[1])
		}
	}
	if len(ids) == 0 {
		ids = []string{"benchmark-failure"}
	}
	return engine.ModelResponse{Metadata: domain.ModelMetadata{Provider: "fake", Model: "eval-v1"}, Hypotheses: []engine.ModelHypothesis{
		{Statement: "division by zero in application code", AffectedComponent: "application", SupportingEvidenceIDs: ids[:1], PredictedObservations: []string{"source boundary is observed"}, Confidence: .7},
		{Statement: "environment configuration mismatch", AffectedComponent: "environment", SupportingEvidenceIDs: ids[:1], PredictedObservations: []string{"runtime changes alter failure"}, Confidence: .3},
	}}, nil
}

func (p fakeProvider) GeneratePatches(_ context.Context, request engine.PatchRequest) ([]domain.PatchProposal, error) {
	var ids []domain.ID
	if len(request.Hypotheses) > 0 {
		ids = []domain.ID{request.Hypotheses[0].ID}
	}
	return []domain.PatchProposal{{HypothesisIDs: ids, ChangedFiles: []string{"bug.py"}, Diff: p.diff, Explanation: "fix division by zero", ExpectedBehavior: "zero is handled", Metadata: domain.ModelMetadata{Provider: "fake", Model: "eval-v1"}}}, nil
}

func TestValidateSuiteAndSummarizeIncompleteTrials(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "bug.py"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	suite := domain.BenchmarkSuite{ID: "python-small", Version: "1", Cases: []domain.BenchmarkCase{{ID: "case-1", SuiteID: "python-small", Version: "1", RepoPath: repo, BuggyRevision: "bug", KnownGoodRevision: "good", ReproductionCommand: []string{"python3", "bug.py"}, RootCause: "division by zero"}}}
	if err := ValidateSuite(suite); err != nil {
		t.Fatal(err)
	}
	summary := Summarize("eval", suite, []domain.EvaluationTrial{{ID: "t", CaseID: "case-1", Strategy: domain.StrategyDirectRepair, Outcome: domain.EvaluationIncomplete}})
	if summary.Trials != 1 || summary.SuccessRate != 0 || len(summary.Warnings) == 0 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if _, _, ok := ConfidenceInterval(1, 1); ok {
		t.Fatal("small sample should not claim confidence interval")
	}
	comparison := CompareStrategies(domain.StrategyDirectRepair, domain.StrategyEvidenceGuided, []domain.EvaluationTrial{
		{CaseID: "a", Strategy: domain.StrategyDirectRepair, Outcome: domain.EvaluationSuccess},
		{CaseID: "a", Strategy: domain.StrategyEvidenceGuided, Outcome: domain.EvaluationFailure},
	})
	if comparison.AbsoluteDifference != -1 || comparison.PairedTrials != 1 {
		t.Fatalf("unexpected paired comparison: %+v", comparison)
	}
}

func TestRootCauseMatchIgnoresFillerWords(t *testing.T) {
	if !rootCauseMatch("division by zero at the input boundary", "The divisor causes division by zero at the input boundary.") {
		t.Fatal("expected equivalent division-boundary diagnosis to match")
	}
	if rootCauseMatch("input state is mutated during transformation", "Add a regression test for add_marker.") {
		t.Fatal("unrelated test addition must not match the state-mutation cause")
	}
}

func TestRunSuitePersistsDirectAndEvidenceGuidedTrials(t *testing.T) {
	repo := t.TempDir()
	files := map[string]string{
		"bug.py":      "def divide(value):\n    return 10 / value\n",
		"test_bug.py": "from bug import divide\ndivide(0)\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", args, out)
		}
	}
	run("git", "init", "-q")
	run("git", "add", ".")
	run("git", "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "base")
	store, err := persistence.Open(filepath.Join(t.TempDir(), "eval.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy := execution.Policy{AllowedCommands: map[string]bool{"python3": true}, AllowedDirs: map[string]bool{repo: true}, AllowedDirPrefixes: []string{os.TempDir()}, AllowedEnviron: map[string]bool{}, MaxOutput: 64 << 10, Timeout: 10 * time.Second}
	diff := "--- a/bug.py\n+++ b/bug.py\n@@ -1,2 +1,2 @@\n def divide(value):\n-    return 10 / value\n+    return 0 if value == 0 else 10 / value\n"
	suite := domain.BenchmarkSuite{ID: "eval-suite", Version: "1", Description: "deterministic Python case", Cases: []domain.BenchmarkCase{{ID: "division-zero", SuiteID: "eval-suite", Version: "1", RepoPath: repo, Repository: ".", BuggyRevision: gitHead(repo), KnownGoodRevision: "known-good-fixture", ReproductionCommand: []string{"python3", "test_bug.py"}, RootCause: "division by zero", ExpectedCorrection: "guard zero divisor", Category: "boundary", Difficulty: "small", License: "test-fixture", Provenance: "local deterministic fixture"}}}
	summary, err := RunSuite(context.Background(), Config{Suite: suite, Strategies: []domain.EvaluationStrategy{domain.StrategyDirectRepair, domain.StrategyEvidenceGuided, domain.StrategyEvidenceOnly, domain.StrategyHypothesesOnly}, Budget: 20, Timeout: 5 * time.Second, Store: store, Provider: fakeProvider{diff: diff}, Executor: execution.NewLocalExecutor(policy, execution.NewArtifactFactory(filepath.Join(t.TempDir(), "artifacts")))})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("comparative evaluation: %s", ReportText(summary))
	if summary.Trials != 4 || summary.Completed != 4 || summary.Successes != 2 {
		t.Fatalf("unexpected evaluation summary: %+v", summary)
	}
	trials, err := store.ListEvaluationTrials(summary.EvaluationID)
	if err != nil || len(trials) != 4 {
		t.Fatalf("trials not persisted: %v %d", err, len(trials))
	}
	if text := ReportText(summary); !strings.Contains(text, "direct_repair") || !strings.Contains(text, "evidence_guided") {
		t.Fatalf("report missing strategies: %s", text)
	}
	if _, err := store.GetEvaluationSummary(summary.EvaluationID); err != nil {
		t.Fatal(err)
	}
}

func gitHead(repo string) string {
	out, _ := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	return strings.TrimSpace(string(out))
}
