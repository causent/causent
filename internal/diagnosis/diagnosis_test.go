package diagnosis

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/causent/causent/internal/execution"
)

// testExecutor runs only sh and only inside the OS temp tree, which is where
// isolated worktrees and test repositories live.
func testExecutor(t *testing.T) execution.Executor {
	t.Helper()
	policy := execution.Policy{
		AllowedCommands:    map[string]bool{"sh": true},
		AllowedDirPrefixes: []string{os.TempDir()},
		AllowedEnviron:     map[string]bool{},
		MaxOutput:          64 << 10,
		Timeout:            30 * time.Second,
	}
	return execution.NewLocalExecutor(policy, execution.NewArtifactFactory(t.TempDir()))
}

func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	git(t, dir, "config", "user.email", "test@example.com")
	git(t, dir, "config", "user.name", "causent test")
	git(t, dir, "config", "commit.gpgsign", "false")
	return dir
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func commit(t *testing.T, dir, message string, files map[string]string) string {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", message)
	return git(t, dir, "rev-parse", "HEAD")
}

// failingRepo has one passing commit and then one commit that makes run.sh fail.
func failingRepo(t *testing.T) (dir, good, bad string) {
	t.Helper()
	dir = newRepo(t)
	good = commit(t, dir, "good state", map[string]string{
		"run.sh": "#!/bin/sh\nif [ -f broken ]; then echo 'failing: broken marker present' >&2; exit 1; fi\nexit 0\n",
	})
	bad = commit(t, dir, "introduce broken marker", map[string]string{"broken": "yes\n"})
	return dir, good, bad
}

func TestDiagnoseReproducibleFailure(t *testing.T) {
	dir, _, bad := failingRepo(t)
	report, err := Run(context.Background(), Config{
		RepoPath: dir,
		Command:  []string{"sh", "run.sh"},
		Attempts: 3,
		Timeout:  30 * time.Second,
		Executor: testExecutor(t),
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Classification != ClassRealRegression {
		t.Fatalf("classification = %s, want %s", report.Classification, ClassRealRegression)
	}
	if report.Refused {
		t.Fatalf("refused unexpectedly: %s", report.RefusalReason)
	}
	if report.Baseline.Attempts != 3 || report.Baseline.Failures != 3 {
		t.Fatalf("baseline = %d attempts / %d failures", report.Baseline.Attempts, report.Baseline.Failures)
	}
	if report.Localization.HeadCommit != bad {
		t.Fatalf("head = %s, want %s", report.Localization.HeadCommit, bad)
	}
	if len(report.Evidence) == 0 || len(report.Claims) == 0 {
		t.Fatal("expected evidence and claims")
	}
	for _, claim := range report.Claims {
		if len(claim.Supporting) == 0 {
			t.Fatalf("claim %s has no supporting evidence", claim.ID)
		}
	}
	if report.Confidence < RefusalConfidence {
		t.Fatalf("confidence %.2f below refusal threshold for a deterministic failure", report.Confidence)
	}
}

func TestDiagnoseFlakyClassification(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "alternating script", map[string]string{
		"flaky.sh": "#!/bin/sh\nn=$(cat count 2>/dev/null || echo 0)\nn=$((n+1))\necho $n > count\nif [ $((n % 2)) -eq 0 ]; then exit 0; fi\n echo 'alternating failure' >&2\nexit 1\n",
	})
	report, err := Run(context.Background(), Config{
		RepoPath: dir,
		Command:  []string{"sh", "flaky.sh"},
		Attempts: 4,
		Timeout:  30 * time.Second,
		Executor: testExecutor(t),
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Classification != ClassFlaky {
		t.Fatalf("classification = %s, want %s (failures=%d passes=%d)", report.Classification, ClassFlaky, report.Baseline.Failures, report.Baseline.Passes)
	}
	if report.Refused {
		t.Fatalf("flaky classification must not be refused: %s", report.RefusalReason)
	}
}

func TestDiagnoseRefusesWithoutReproduction(t *testing.T) {
	dir := newRepo(t)
	good := commit(t, dir, "green", map[string]string{"run.sh": "#!/bin/sh\nexit 0\n"})
	report, err := Run(context.Background(), Config{
		RepoPath: dir,
		Command:  []string{"sh", "run.sh"},
		Attempts: 2,
		Timeout:  30 * time.Second,
		Executor: testExecutor(t),
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Classification != ClassNotReproduced {
		t.Fatalf("classification = %s, want %s", report.Classification, ClassNotReproduced)
	}
	if !report.Refused {
		t.Fatal("expected refusal when the failure does not reproduce")
	}
	if !strings.Contains(report.RefusalReason, "did not fail") {
		t.Fatalf("refusal reason = %q", report.RefusalReason)
	}
	if report.Confidence != 0 {
		t.Fatalf("confidence = %.2f, want 0", report.Confidence)
	}
	if report.Localization.HeadCommit != good {
		t.Fatalf("head = %s, want %s", report.Localization.HeadCommit, good)
	}
	if len(report.Claims) != 0 {
		t.Fatal("a refused diagnosis must not make claims")
	}
}

func TestDiagnoseBisectLocalization(t *testing.T) {
	dir := newRepo(t)
	good := commit(t, dir, "good", map[string]string{
		"run.sh": "#!/bin/sh\nif [ -f broken ]; then exit 1; fi\nexit 0\n",
	})
	commit(t, dir, "still good", map[string]string{"notes.txt": "unrelated\n"})
	bad := commit(t, dir, "bad", map[string]string{"broken": "yes\n"})

	report, err := Run(context.Background(), Config{
		RepoPath:   dir,
		Command:    []string{"sh", "run.sh"},
		Attempts:   2,
		Timeout:    30 * time.Second,
		Executor:   testExecutor(t),
		GoodRef:    good,
		MaxCommits: 10,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Refused {
		t.Fatalf("refused unexpectedly: %s", report.RefusalReason)
	}
	if report.Localization.LastKnownGood != good {
		t.Fatalf("last known good = %s, want %s", report.Localization.LastKnownGood, good)
	}
	if report.Localization.BisectResult != bad {
		t.Fatalf("bisect result = %q (status %q), want %s", report.Localization.BisectResult, report.Localization.BisectStatus, bad)
	}
	if report.Localization.FirstKnownBad != bad {
		t.Fatalf("first known bad = %s, want %s", report.Localization.FirstKnownBad, bad)
	}
	if len(report.Localization.LikelyFiles) == 0 {
		t.Fatal("expected likely files from the commit range")
	}
	found := false
	for _, file := range report.Localization.LikelyFiles {
		if file == "run.sh" || file == "broken" {
			found = true
		}
	}
	if !found {
		t.Fatalf("likely files = %v, want a file changed between good and bad", report.Localization.LikelyFiles)
	}
	if !hasEvidence(report.Evidence, "E-git-bisect") {
		t.Fatal("expected E-git-bisect evidence")
	}
}

func TestDiagnoseWalksHistoryWithoutBisect(t *testing.T) {
	dir, good, bad := failingRepo(t)
	report, err := Run(context.Background(), Config{
		RepoPath: dir,
		Command:  []string{"sh", "run.sh"},
		Attempts: 1,
		Timeout:  30 * time.Second,
		Executor: testExecutor(t),
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.Localization.LastKnownGood != good {
		t.Fatalf("last known good = %s, want %s", report.Localization.LastKnownGood, good)
	}
	if report.Localization.FirstKnownBad != bad {
		t.Fatalf("first known bad = %s, want %s", report.Localization.FirstKnownBad, bad)
	}
	if report.Localization.BisectResult != "" {
		t.Fatalf("unexpected bisect result without --good: %s", report.Localization.BisectResult)
	}
}

func TestBundleCreationAndIntegrity(t *testing.T) {
	dir, _, _ := failingRepo(t)
	bundleDir := filepath.Join(t.TempDir(), "bundle")
	report, err := Run(context.Background(), Config{
		RepoPath:  dir,
		Command:   []string{"sh", "run.sh"},
		Attempts:  2,
		Timeout:   30 * time.Second,
		Executor:  testExecutor(t),
		BundleDir: bundleDir,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if report.BundlePath == "" {
		t.Fatal("expected a bundle path")
	}
	for _, name := range []string{
		"manifest.json", "events.jsonl", "environment.json",
		"baseline-results.json", "bisect-results.json",
		"evidence", "replay.sh", "checksums.txt",
	} {
		if _, err := os.Stat(filepath.Join(bundleDir, name)); err != nil {
			t.Fatalf("missing bundle file %s: %v", name, err)
		}
	}
	if err := VerifyChecksums(bundleDir); err != nil {
		t.Fatalf("checksums: %v", err)
	}

	manifest, err := ReadManifest(bundleDir)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if manifest.Diagnosis.Classification != report.Classification {
		t.Fatalf("manifest classification = %s, want %s", manifest.Diagnosis.Classification, report.Classification)
	}

	events := readEvents(t, filepath.Join(bundleDir, "events.jsonl"))
	for _, required := range []string{
		EventReproductionStarted, EventReproductionCompleted, EventClassificationComplete,
		EventLocalizationStarted, EventLocalizationCompleted, EventBundleCreated, EventDiagnosisCompleted,
	} {
		if !containsString(events, required) {
			t.Fatalf("events.jsonl missing %s; got %v", required, events)
		}
	}
	for _, ev := range report.Evidence {
		if _, err := os.Stat(filepath.Join(bundleDir, "evidence", ev.ID+".txt")); err != nil {
			t.Fatalf("missing evidence file for %s: %v", ev.ID, err)
		}
	}

	// Tampering with any recorded file must fail integrity verification.
	evidenceFile := filepath.Join(bundleDir, "evidence", report.Evidence[0].ID+".txt")
	if err := os.WriteFile(evidenceFile, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyChecksums(bundleDir); err == nil {
		t.Fatal("expected checksum mismatch after tampering")
	}
}

func TestReplayMatchesRecordedConclusion(t *testing.T) {
	dir, _, _ := failingRepo(t)
	bundleDir := filepath.Join(t.TempDir(), "bundle")
	report, err := Run(context.Background(), Config{
		RepoPath:  dir,
		Command:   []string{"sh", "run.sh"},
		Attempts:  2,
		Timeout:   30 * time.Second,
		Executor:  testExecutor(t),
		BundleDir: bundleDir,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	result, err := Replay(context.Background(), ReplayConfig{
		BundleDir: bundleDir,
		Executor:  testExecutor(t),
		Timeout:   30 * time.Second,
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !result.Matched {
		t.Fatalf("replay mismatch: recorded %s observed %s notes=%v", result.RecordedClassification, result.ObservedClassification, result.Notes)
	}
	if result.ObservedClassification != report.Classification {
		t.Fatalf("observed classification = %s, want %s", result.ObservedClassification, report.Classification)
	}
	if len(result.ObservedAttempts) != len(report.Baseline.Results) {
		t.Fatalf("replayed %d attempts, want %d", len(result.ObservedAttempts), len(report.Baseline.Results))
	}
}

func TestReplayDetectsMismatch(t *testing.T) {
	dir, _, _ := failingRepo(t)
	bundleDir := filepath.Join(t.TempDir(), "bundle")
	if _, err := Run(context.Background(), Config{
		RepoPath:  dir,
		Command:   []string{"sh", "run.sh"},
		Attempts:  2,
		Timeout:   30 * time.Second,
		Executor:  testExecutor(t),
		BundleDir: bundleDir,
	}); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Simulate a bundle whose recorded conclusion no longer holds, while
	// keeping the bundle internally consistent (valid checksums).
	manifest, err := ReadManifest(bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Diagnosis.Classification = ClassFlaky
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "manifest.json"), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteChecksums(bundleDir); err != nil {
		t.Fatal(err)
	}

	result, err := Replay(context.Background(), ReplayConfig{
		BundleDir: bundleDir,
		Executor:  testExecutor(t),
		Timeout:   30 * time.Second,
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if result.Matched {
		t.Fatal("expected replay mismatch after the recorded conclusion changed")
	}
	if result.ObservedClassification != ClassRealRegression {
		t.Fatalf("observed classification = %s, want %s", result.ObservedClassification, ClassRealRegression)
	}
}

func TestReplayRejectsTamperedBundle(t *testing.T) {
	dir, _, _ := failingRepo(t)
	bundleDir := filepath.Join(t.TempDir(), "bundle")
	if _, err := Run(context.Background(), Config{
		RepoPath:  dir,
		Command:   []string{"sh", "run.sh"},
		Attempts:  1,
		Timeout:   30 * time.Second,
		Executor:  testExecutor(t),
		BundleDir: bundleDir,
	}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "baseline-results.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Replay(context.Background(), ReplayConfig{
		BundleDir: bundleDir,
		Executor:  testExecutor(t),
		Timeout:   30 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("expected integrity error, got %v", err)
	}
}

func TestRefusalEvidenceRemainsSeparateFromClaims(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "green", map[string]string{"run.sh": "#!/bin/sh\nexit 0\n"})
	report, err := Run(context.Background(), Config{
		RepoPath: dir,
		Command:  []string{"sh", "run.sh"},
		Attempts: 1,
		Timeout:  30 * time.Second,
		Executor: testExecutor(t),
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(report.Evidence) == 0 {
		t.Fatal("evidence must be recorded even when the diagnosis is refused")
	}
	if len(report.Claims) != 0 {
		t.Fatalf("claims must be empty when refused, got %d", len(report.Claims))
	}
	if report.Confidence != 0 {
		t.Fatalf("confidence = %.2f, want 0", report.Confidence)
	}
}

func readEvents(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev EventRecord
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad event line %q: %v", line, err)
		}
		names = append(names, ev.Event)
	}
	return names
}

func hasEvidence(items []EvidenceItem, id string) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

var errUnused = errors.New("unused")

var _ = errUnused
