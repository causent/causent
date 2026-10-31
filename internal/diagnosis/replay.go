package diagnosis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yashbhu/Hades/internal/execution"
)

// ReplayConfig controls one replay of a recorded diagnosis bundle.
type ReplayConfig struct {
	BundleDir string
	// RepoPath overrides the recorded repository path, for a moved checkout.
	RepoPath string
	Executor execution.Executor
	// Timeout overrides the timeout used for the original reproduction.
	Timeout time.Duration
}

// ReplayResult compares the recorded conclusion with a fresh re-run of the
// recorded checks.
type ReplayResult struct {
	BundlePath string `json:"bundle_path"`
	RepoPath   string `json:"repo_path"`
	Commit     string `json:"commit"`
	Command    string `json:"command"`

	RecordedClassification Classification `json:"recorded_classification"`
	ObservedClassification Classification `json:"observed_classification"`
	RecordedRefused        bool           `json:"recorded_refused"`
	ObservedRefused        bool           `json:"observed_refused"`

	RecordedAttempts []Attempt `json:"recorded_attempts"`
	ObservedAttempts []Attempt `json:"observed_attempts"`

	Matched bool     `json:"matched"`
	Notes   []string `json:"notes,omitempty"`
}

// Replay verifies a bundle, re-runs its recorded reproduction checks at the
// recorded commit, and reports whether the same conclusion is reached. It
// deliberately does not re-run git bisect: replay answers "does the failure and
// its classification still reproduce", not "was the original localization
// correct".
func Replay(ctx context.Context, cfg ReplayConfig) (ReplayResult, error) {
	result := ReplayResult{BundlePath: cfg.BundleDir}
	if cfg.BundleDir == "" {
		return result, fmt.Errorf("bundle path is required")
	}
	if cfg.Executor == nil {
		return result, fmt.Errorf("executor is required")
	}
	abs, err := filepath.Abs(cfg.BundleDir)
	if err != nil {
		return result, err
	}
	result.BundlePath = abs

	if err := VerifyChecksums(abs); err != nil {
		return result, err
	}
	manifest, err := ReadManifest(abs)
	if err != nil {
		return result, err
	}
	recorded := manifest.Diagnosis
	result.RecordedClassification = recorded.Classification
	result.RecordedRefused = recorded.Refused
	result.RecordedAttempts = recorded.Baseline.Results
	result.Command = strings.Join(recorded.Baseline.Command, " ")
	if len(recorded.Baseline.Command) == 0 {
		return result, fmt.Errorf("bundle records no command to replay")
	}

	repo := cfg.RepoPath
	if repo == "" {
		repo = recorded.Environment.RepoPath
	}
	if repo == "" {
		repo = recorded.RepoPath
	}
	if repo == "" {
		return result, fmt.Errorf("bundle records no repository path; pass --repo")
	}
	if info, err := os.Stat(repo); err != nil || !info.IsDir() {
		return result, fmt.Errorf("repository path is not a directory: %s", repo)
	}
	result.RepoPath = repo

	commit := recorded.Environment.HeadCommit
	if commit == "" {
		commit = recorded.Localization.HeadCommit
	}
	if commit == "" {
		return result, fmt.Errorf("bundle records no commit to replay at")
	}
	if resolved := strings.TrimSpace(gitOutput(repo, "rev-parse", "--verify", commit+"^{commit}")); resolved == "" {
		return result, fmt.Errorf("recorded commit %s does not exist in %s", commit, repo)
	} else {
		commit = resolved
	}
	result.Commit = commit

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	attempts := len(recorded.Baseline.Results)
	if attempts <= 0 {
		attempts = DefaultAttempts
	}

	d := &Diagnoser{cfg: Config{
		RepoPath: repo,
		Command:  recorded.Baseline.Command,
		Attempts: attempts,
		Timeout:  timeout,
		Executor: cfg.Executor,
	}}

	dir, cleanup, err := isolatedWorkspace(ctx, repo, commit)
	if err != nil {
		return result, fmt.Errorf("create isolated workspace: %w", err)
	}
	defer cleanup()

	for i := 0; i < attempts; i++ {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		result.ObservedAttempts = append(result.ObservedAttempts, d.runOnce(ctx, dir, i))
	}

	baseline := Baseline{Attempts: attempts, Command: recorded.Baseline.Command, Results: result.ObservedAttempts}
	for _, a := range result.ObservedAttempts {
		switch {
		case a.Failed():
			baseline.Failures++
		case a.Passed():
			baseline.Passes++
		}
		if a.TimedOut {
			baseline.TimedOut++
		}
	}
	result.ObservedClassification = Classify(result.ObservedAttempts)
	if _, refused := refusalReason(result.ObservedClassification, baseline); refused {
		result.ObservedRefused = true
	} else if result.ObservedClassification != recorded.Classification {
		// A different classification is already a mismatch; do not invent a
		// refusal threshold check from a localization we did not re-execute.
		result.ObservedRefused = false
	} else {
		result.ObservedRefused = recorded.Refused
	}
	result.Matched = result.ObservedClassification == result.RecordedClassification &&
		result.ObservedRefused == result.RecordedRefused

	result.Notes = append(result.Notes,
		"replay re-ran the recorded reproduction command only; git bisect and localization were not re-executed",
	)
	if result.ObservedClassification != result.RecordedClassification {
		result.Notes = append(result.Notes, fmt.Sprintf(
			"classification changed from %s to %s", result.RecordedClassification, result.ObservedClassification))
	}
	if result.ObservedRefused != result.RecordedRefused {
		result.Notes = append(result.Notes, fmt.Sprintf(
			"refusal changed from %t to %t", result.RecordedRefused, result.ObservedRefused))
	}
	return result, nil
}
