package engine

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/causent/causent/internal/domain"
	"github.com/causent/causent/internal/execution"
	"github.com/causent/causent/internal/persistence"
)

type patchProvider struct{ diff string }

func (p patchProvider) Generate(_ context.Context, _ ModelRequest) (ModelResponse, error) {
	return ModelResponse{}, nil
}

type retryPatchProvider struct {
	attempts int
	diff     string
	feedback []string
}

func (p *retryPatchProvider) Generate(context.Context, ModelRequest) (ModelResponse, error) {
	return ModelResponse{}, nil
}

func (p *retryPatchProvider) GeneratePatches(_ context.Context, request PatchRequest) ([]domain.PatchProposal, error) {
	p.attempts++
	p.feedback = append(p.feedback, request.ValidationError)
	diff := p.diff
	if p.attempts == 1 {
		diff = "--- a/missing.py\n+++ b/missing.py\n"
	}
	return []domain.PatchProposal{{HypothesisIDs: []domain.ID{"h1"}, ChangedFiles: []string{"bug.py"}, Diff: diff, Explanation: "fix", ExpectedBehavior: "passes", Metadata: domain.ModelMetadata{Provider: "fake"}}}, nil
}

func (p patchProvider) GeneratePatches(context.Context, PatchRequest) ([]domain.PatchProposal, error) {
	return []domain.PatchProposal{{HypothesisIDs: []domain.ID{"h1"}, ChangedFiles: []string{"bug.py"}, Diff: p.diff, Explanation: "fix", ExpectedBehavior: "passes", Metadata: domain.ModelMetadata{Provider: "fake"}}}, nil
}

type patchExecutor struct{}

func (patchExecutor) Run(context.Context, domain.ExecutionRequest) (domain.ExecutionResult, error) {
	return domain.ExecutionResult{ExitCode: 0, StartedAt: time.Now(), FinishedAt: time.Now()}, nil
}

type feedbackPatchProvider struct {
	diff     string
	feedback []string
}

func (*feedbackPatchProvider) Generate(context.Context, ModelRequest) (ModelResponse, error) {
	return ModelResponse{}, nil
}

func (p *feedbackPatchProvider) GeneratePatches(_ context.Context, request PatchRequest) ([]domain.PatchProposal, error) {
	p.feedback = append(p.feedback, request.ValidationError)
	return []domain.PatchProposal{{
		HypothesisIDs: []domain.ID{"h1"}, ChangedFiles: []string{"bug.py"}, Diff: p.diff,
		Explanation: "fix", ExpectedBehavior: "passes", Metadata: domain.ModelMetadata{Provider: "fake"},
	}}, nil
}

type feedbackPatchExecutor struct{ calls int }

func (e *feedbackPatchExecutor) Run(context.Context, domain.ExecutionRequest) (domain.ExecutionResult, error) {
	e.calls++
	result := domain.ExecutionResult{ExitCode: 0, StartedAt: time.Now(), FinishedAt: time.Now()}
	if e.calls == 1 {
		result.ExitCode = 1
		result.Stderr = "candidate still fails"
	}
	return result, nil
}

func initGitRepo(t *testing.T, repo string, files map[string]string) {
	t.Helper()
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
	run("git", "-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "-qm", "base")
}

func TestGenerateAndVerifyPatchUsesDisposableWorkspace(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo, map[string]string{"bug.py": "return 1\n"})
	store, err := persistence.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	inv := domain.Investigation{ID: "inv-patch", RepoPath: repo, Command: []string{"python3", "bug.py"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := store.SaveInvestigation(inv); err != nil {
		t.Fatal(err)
	}
	diff := "--- a/bug.py\n+++ b/bug.py\n@@ -1 +1 @@\n-return 1\n+return 0\n"
	i := &Investigator{Store: store, Provider: patchProvider{diff: diff}, Executor: patchExecutor{}}
	patch, err := i.GenerateAndVerifyPatch(context.Background(), inv, domain.Reproduction{Result: &domain.ExecutionResult{ExitCode: 1}}, nil, []domain.Hypothesis{{ID: "h1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if patch.VerificationStatus != string(domain.VerificationPassed) || patch.Digest == "" {
		t.Fatalf("unexpected patch result: %+v", patch)
	}
	data, _ := os.ReadFile(filepath.Join(repo, "bug.py"))
	if string(data) != "return 1\n" {
		t.Fatalf("original repository changed: %q", data)
	}
	if _, err := store.GetVerificationReport(patch.ID); err != nil {
		t.Fatalf("verification report not persisted: %v", err)
	}
}

func TestGenerateAndVerifyPatchFeedsVerificationFailureBackToNextAttempt(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo, map[string]string{"bug.py": "return 1\n"})
	store, err := persistence.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	inv := domain.Investigation{ID: "inv-feedback", RepoPath: repo, Command: []string{"python3", "bug.py"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := store.SaveInvestigation(inv); err != nil {
		t.Fatal(err)
	}
	provider := &feedbackPatchProvider{diff: "--- a/bug.py\n+++ b/bug.py\n@@ -1 +1 @@\n-return 1\n+return 0\n"}
	executor := &feedbackPatchExecutor{}
	investigator := &Investigator{
		Store: store, Provider: provider, Executor: executor, PatchAttempts: 2,
	}
	patch, err := investigator.GenerateAndVerifyPatch(context.Background(), inv, domain.Reproduction{Result: &domain.ExecutionResult{ExitCode: 1}}, nil, []domain.Hypothesis{{ID: "h1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if patch == nil || patch.VerificationStatus != string(domain.VerificationPassed) {
		t.Fatalf("expected second attempt to pass, got %+v", patch)
	}
	if executor.calls != 2 || len(provider.feedback) != 2 || !strings.Contains(provider.feedback[1], "verification exit_code=1") {
		t.Fatalf("verification feedback was not provided: calls=%d feedback=%q", executor.calls, provider.feedback)
	}
}

func TestValidatePatchRejectsTraversal(t *testing.T) {
	err := validatePatchProposal(domain.Investigation{RepoPath: t.TempDir()}, nil, domain.PatchProposal{
		ChangedFiles: []string{"../outside.py"}, Diff: "--- a/../outside.py\n+++ b/../outside.py\n"})
	if err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestValidateStructuredEditTargetsRejectsBenchmarkTestFiles(t *testing.T) {
	err := validateStructuredEditTargets(domain.PatchProposal{
		Edits: []domain.EditProposal{{File: "test_bug.py", OldText: "assert True", NewText: "assert False"}},
	})
	if err == nil || !strings.Contains(err.Error(), "edit the implementation file") {
		t.Fatalf("expected actionable test-file rejection, got %v", err)
	}
}

func TestMaterializeStructuredEditBuildsValidDiff(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo, map[string]string{"bug.py": "return 1\n"})
	proposal := domain.PatchProposal{Edits: []domain.EditProposal{{File: "bug.py", OldText: "return 1", NewText: "return 0"}}}
	if err := materializeStructuredEdits(domain.Investigation{RepoPath: repo}, &proposal); err != nil {
		t.Fatal(err)
	}
	if proposal.ChangedFiles[0] != "bug.py" || !strings.Contains(proposal.Diff, "--- a/bug.py") || !strings.Contains(proposal.Diff, "+++ b/bug.py") {
		t.Fatalf("unexpected materialized proposal: %+v", proposal)
	}
	if err := validatePatchProposal(domain.Investigation{RepoPath: repo}, nil, proposal); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateAndVerifyPatchRetriesInvalidCandidate(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo, map[string]string{"bug.py": "return 1\n"})
	store, err := persistence.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	inv := domain.Investigation{ID: "inv-retry", RepoPath: repo, Command: []string{"python3", "bug.py"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := store.SaveInvestigation(inv); err != nil {
		t.Fatal(err)
	}
	provider := &retryPatchProvider{diff: "--- a/bug.py\n+++ b/bug.py\n@@ -1 +1 @@\n-return 1\n+return 0\n"}
	i := &Investigator{Store: store, Provider: provider, Executor: patchExecutor{}}
	if _, err := i.GenerateAndVerifyPatch(context.Background(), inv, domain.Reproduction{}, nil, []domain.Hypothesis{{ID: "h1"}}, nil); err != nil {
		t.Fatal(err)
	}
	if provider.attempts != 2 {
		t.Fatalf("expected one bounded retry, got %d attempts", provider.attempts)
	}
	if provider.feedback[0] != "" || !strings.Contains(provider.feedback[1], "diff does not target declared file") {
		t.Fatalf("retry did not receive actionable validation feedback: %#v", provider.feedback)
	}
}

func TestDeterministicPatchValidationMatrix(t *testing.T) {
	repo := t.TempDir()
	initGitRepo(t, repo, map[string]string{
		"bug.py":      "def divide(value):\n    return 10 / value\n",
		"test_bug.py": "from bug import divide\nassert divide(0) == 0\n",
	})
	inv := domain.Investigation{RepoPath: repo}
	tests := []struct {
		name string
		p    domain.PatchProposal
		msg  string
	}{
		{
			name: "test file edit",
			p:    domain.PatchProposal{Edits: []domain.EditProposal{{File: "test_bug.py", OldText: "divide(0)", NewText: "divide(1)"}}},
			msg:  "edit the implementation file",
		},
		{
			name: "traversal",
			p:    domain.PatchProposal{Edits: []domain.EditProposal{{File: "../bug.py", OldText: "return 10 / value", NewText: "return 0"}}},
			msg:  "escapes repository",
		},
		{
			name: "stale anchor",
			p:    domain.PatchProposal{Edits: []domain.EditProposal{{File: "bug.py", OldText: "return 10 / missing", NewText: "return 0"}}},
			msg:  "match exactly once",
		},
		{
			name: "duplicate anchor",
			p:    domain.PatchProposal{Edits: []domain.EditProposal{{File: "bug.py", OldText: "value", NewText: "input"}}},
			msg:  "match exactly once",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateStructuredEditTargets(tt.p); err != nil {
				if tt.name == "test file edit" && !strings.Contains(err.Error(), tt.msg) {
					t.Fatalf("unexpected test-file error: %v", err)
				}
				return
			}
			err := materializeStructuredEdits(inv, &tt.p)
			if err == nil || !strings.Contains(err.Error(), tt.msg) {
				t.Fatalf("expected %q, got %v", tt.msg, err)
			}
		})
	}
}

func TestGenerateAndVerifyPatchWithRealPythonExecution(t *testing.T) {
	repo := t.TempDir()
	files := map[string]string{
		"bug.py":             "def divide(value):\n    return 10 / value\n",
		"test_bug.py":        "from bug import divide\ndivide(0)\n",
		"test_regression.py": "from bug import divide\nassert divide(2) == 5\n",
	}
	initGitRepo(t, repo, files)
	store, err := persistence.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	inv := domain.Investigation{ID: "inv-real-patch", RepoPath: repo, Command: []string{"python3", "test_bug.py"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := store.SaveInvestigation(inv); err != nil {
		t.Fatal(err)
	}
	executor := realPythonExecutor(t, repo)
	baseline, err := executor.Run(context.Background(), domain.ExecutionRequest{Command: inv.Command, Dir: repo, Timeout: 5 * time.Second, MaxOutput: 64 * 1024})
	if err != nil || baseline.ExitCode == 0 {
		t.Fatalf("expected failing baseline, result=%+v err=%v", baseline, err)
	}
	diff := "--- a/bug.py\n+++ b/bug.py\n@@ -1,2 +1,2 @@\n def divide(value):\n-    return 10 / value\n+    return 0 if value == 0 else 10 / value\n"
	investigator := &Investigator{Store: store, Provider: patchProvider{diff: diff}, Executor: executor}
	patch, err := investigator.GenerateAndVerifyPatch(context.Background(), inv, domain.Reproduction{Result: &baseline}, nil, []domain.Hypothesis{{ID: "h1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	report, err := store.GetVerificationReport(patch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != domain.VerificationPassed || !report.OriginalResolved || !report.RegressionsPassed {
		t.Fatalf("unexpected real verification report: %+v", report)
	}
	original, _ := os.ReadFile(filepath.Join(repo, "bug.py"))
	if string(original) != files["bug.py"] {
		t.Fatalf("original repository changed: %q", original)
	}
	if len(report.RegressionResults) != 1 {
		t.Fatalf("regression results = %d, want 1", len(report.RegressionResults))
	}
}

func TestInvestigateRunsCompletePythonPatchWorkflow(t *testing.T) {
	repo := t.TempDir()
	files := map[string]string{
		"bug.py":             "def divide(value):\n    return 10 / value\n",
		"test_bug.py":        "from bug import divide\ndivide(0)\n",
		"test_regression.py": "from bug import divide\nassert divide(2) == 5\n",
	}
	initGitRepo(t, repo, files)
	store, err := persistence.Open(filepath.Join(t.TempDir(), "workflow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	investigator := &Investigator{Store: store, Executor: realPythonExecutor(t, repo), Provider: HeuristicProvider{}}
	_, result, err := investigator.Investigate(context.Background(), repo, []string{"python3", "test_bug.py"}, 5*time.Second, 20)
	if err != nil {
		t.Fatal(err)
	}
	if result.Patch == nil || result.Patch.VerificationStatus != string(domain.VerificationPassed) {
		t.Fatalf("workflow did not verify patch: patch=%+v report=%s", result.Patch, result.FinalReport)
	}
	original, _ := os.ReadFile(filepath.Join(repo, "bug.py"))
	if string(original) != files["bug.py"] {
		t.Fatalf("workflow modified original repository: %q", original)
	}
}

func realPythonExecutor(t *testing.T, repo string) *execution.LocalExecutor {
	t.Helper()
	return execution.NewLocalExecutor(execution.Policy{
		AllowedCommands:    map[string]bool{"python3": true},
		AllowedDirs:        map[string]bool{repo: true},
		AllowedDirPrefixes: []string{os.TempDir()},
		AllowedEnviron:     map[string]bool{},
		MaxOutput:          64 * 1024,
		Timeout:            10 * time.Second,
	}, execution.NewArtifactFactory(filepath.Join(t.TempDir(), "artifacts")))
}
