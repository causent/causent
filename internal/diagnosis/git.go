package diagnosis

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const gitTimeout = 30 * time.Second

// captureEnvironment records the bounded execution context. No secrets, no
// full environment dump.
func captureEnvironment(repo string) Environment {
	env := Environment{
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		GoVersion:  runtime.Version(),
		GitVersion: strings.TrimSpace(gitOutput(repo, "--version")),
		RepoPath:   repo,
		HeadCommit: strings.TrimSpace(gitOutput(repo, "rev-parse", "HEAD")),
		RecordedAt: time.Now().UTC(),
	}
	if status := gitOutput(repo, "status", "--porcelain"); strings.TrimSpace(status) != "" {
		env.DirtyWorktree = true
	}
	return env
}

// isolatedWorkspace creates a detached git worktree so reproduction never runs
// in the user's checkout. The returned cleanup removes the worktree.
func isolatedWorkspace(ctx context.Context, repo, commit string) (string, func(), error) {
	if commit == "" {
		return "", nil, fmt.Errorf("repository has no commits")
	}
	dir, err := os.MkdirTemp("", "malenia-workspace-*")
	if err != nil {
		return "", nil, err
	}
	if _, err := gitRun(ctx, repo, "worktree", "add", "--detach", dir, commit); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	cleanup := func() {
		_, _ = gitRun(context.Background(), repo, "worktree", "remove", "--force", dir)
		_ = os.RemoveAll(dir)
	}
	return dir, cleanup, nil
}

// workspaceAt checks out one commit in a temporary worktree, runs fn, and
// removes the worktree.
func (d *Diagnoser) workspaceAt(ctx context.Context, commit string, fn func(dir string) error) error {
	if commit == "" {
		return fmt.Errorf("empty commit")
	}
	dir, cleanup, err := isolatedWorkspace(ctx, d.cfg.RepoPath, commit)
	if err != nil {
		return err
	}
	defer cleanup()
	return fn(dir)
}

// passesAt runs the recorded command once at a commit and reports whether it
// exited cleanly.
func (d *Diagnoser) passesAt(ctx context.Context, commit string) bool {
	passed := false
	err := d.workspaceAt(ctx, commit, func(dir string) error {
		attempt := d.runOnce(ctx, dir, 0)
		passed = attempt.Passed()
		return nil
	})
	return err == nil && passed
}

func (d *Diagnoser) localize(ctx context.Context, workspace string, baseline Baseline, comparison *Comparison) (Localization, []EvidenceItem, error) {
	loc := Localization{
		HeadCommit:   strings.TrimSpace(gitOutput(d.cfg.RepoPath, "rev-parse", "HEAD")),
		BisectStatus: "not_attempted",
	}
	if loc.HeadCommit == "" {
		return loc, nil, fmt.Errorf("repository has no HEAD commit")
	}

	var evidence []EvidenceItem

	if d.cfg.GoodRef != "" {
		good := strings.TrimSpace(gitOutput(d.cfg.RepoPath, "rev-parse", d.cfg.GoodRef))
		if good == "" {
			return loc, evidence, fmt.Errorf("known-good revision %q could not be resolved", d.cfg.GoodRef)
		}
		knownGood := comparison != nil && comparison.BaseCommit == good && baselineIsPassing(comparison.Base)
		if !knownGood && !d.passesAt(ctx, good) {
			return loc, evidence, fmt.Errorf("known-good revision %q does not pass the recorded command", d.cfg.GoodRef)
		}
		if !baselineIsFailing(baseline) {
			loc.BisectStatus = "inconclusive: head outcome does not establish a reproducible failure"
		} else {
			loc.LastKnownGood, loc.FirstKnownBad, loc.BisectResult, loc.BisectStatus, loc.BisectLog = d.bisectFromKnownEndpoints(ctx, good, loc.HeadCommit)
		}
	} else if d.cfg.BaseRef != "" {
		if comparison == nil {
			loc.BisectStatus = "inconclusive: base/head comparison did not establish commit outcomes"
		} else if baselineIsFailing(comparison.Base) {
			loc.BisectStatus = "skipped: the failure also reproduces on the PR base; a PR regression is not established"
		} else if baselineIsPassing(comparison.Base) && baselineIsFailing(baseline) {
			good := strings.TrimSpace(comparison.BaseCommit)
			loc.LastKnownGood, loc.FirstKnownBad, loc.BisectResult, loc.BisectStatus, loc.BisectLog = d.bisectFromKnownEndpoints(ctx, good, loc.HeadCommit)
		} else {
			loc.BisectStatus = "inconclusive: base/head outcomes were mixed or timed out; revision search stopped"
		}
	} else if baselineIsFailing(baseline) {
		loc.LastKnownGood, loc.FirstKnownBad, loc.BisectResult, loc.BisectStatus, loc.BisectLog = d.adaptiveWalk(ctx, loc.HeadCommit)
	} else {
		loc.BisectStatus = "inconclusive: head outcome does not establish a reproducible failure"
	}

	if loc.LastKnownGood != "" {
		evidence = append(evidence, EvidenceItem{
			ID:     "E-git-last-good",
			Kind:   "git",
			Source: "git rev-list " + loc.HeadCommit,
			Digest: digestString(loc.LastKnownGood),
			Detail: "last known good commit: " + loc.LastKnownGood,
		})
	}
	if loc.FirstKnownBad != "" {
		evidence = append(evidence, EvidenceItem{
			ID:     "E-git-first-bad",
			Kind:   "git",
			Source: "git rev-list " + loc.HeadCommit,
			Digest: digestString(loc.FirstKnownBad),
			Detail: "first known bad commit: " + loc.FirstKnownBad,
		})
	}
	if loc.BisectLog != "" {
		evidence = append(evidence, EvidenceItem{
			ID:     "E-git-bisect",
			Kind:   "git_bisect",
			Source: "bounded adaptive revision search",
			Digest: digestString(loc.BisectLog),
			Detail: fmt.Sprintf("revision search status: %s\n%s", loc.BisectStatus, bound(loc.BisectLog, MaxEvidenceExcerpt)),
		})
	}

	loc.LikelyFiles, loc.CandidateCommit, loc.CommitRange = d.diffScope(loc)
	if len(loc.LikelyFiles) > 0 {
		evidence = append(evidence, EvidenceItem{
			ID:     "E-git-diff",
			Kind:   "git_diff",
			Source: "git diff --name-only " + loc.CommitRange,
			Digest: digestString(strings.Join(loc.LikelyFiles, "\n")),
			Detail: "files changed in " + loc.CommitRange + ":\n" + strings.Join(loc.LikelyFiles, "\n"),
		})
	}
	if len(loc.CandidateCommit) > 0 {
		var b strings.Builder
		for _, c := range loc.CandidateCommit {
			fmt.Fprintf(&b, "%s %s\n", shortSHA(c.SHA), c.Subject)
		}
		evidence = append(evidence, EvidenceItem{
			ID:     "E-git-history",
			Kind:   "git_history",
			Source: "git log " + loc.CommitRange,
			Digest: digestString(b.String()),
			Detail: b.String(),
		})
	}
	loc.LikelyFunctions = extractFrames(baseline)
	evidence = append(evidence, EvidenceItem{
		ID:     "E-git-head",
		Kind:   "git",
		Source: "git rev-parse HEAD",
		Digest: digestString(loc.HeadCommit),
		Detail: "reproduced at commit: " + loc.HeadCommit,
	})
	return loc, evidence, nil
}

func baselineIsPassing(b Baseline) bool {
	return b.Attempts > 0 && b.Passes == b.Attempts && b.Failures == 0 && b.TimedOut == 0
}

func baselineIsFailing(b Baseline) bool {
	return b.Attempts > 0 && b.Failures == b.Attempts && b.Passes == 0 && b.TimedOut == 0
}

// probeCommit returns a conclusive test result only when the command actually
// passed or failed. Timeouts and execution errors never become negative evidence.
func (d *Diagnoser) probeCommit(ctx context.Context, commit string) (passed, conclusive bool, duration time.Duration) {
	var attempt Attempt
	err := d.workspaceAt(ctx, commit, func(dir string) error {
		attempt = d.runOnce(ctx, dir, 0)
		return nil
	})
	if err != nil || ctx.Err() != nil {
		return false, false, attempt.Duration
	}
	if attempt.Passed() {
		return true, true, attempt.Duration
	}
	if attempt.Failed() {
		return false, true, attempt.Duration
	}
	return false, false, attempt.Duration
}

// adaptiveWalk samples ancestors at exponentially increasing distances. Once
// it finds a passing revision, it bisects only the bracket between that
// revision and the nearest known failing checkpoint.
func (d *Diagnoser) adaptiveWalk(ctx context.Context, head string) (string, string, string, string, string) {
	commits := strings.Fields(strings.TrimSpace(gitOutput(d.cfg.RepoPath, "rev-list", "--first-parent", fmt.Sprintf("--max-count=%d", d.cfg.MaxCommits), head)))
	if len(commits) < 2 {
		return "", head, "", "inconclusive: no ancestor commit is available to probe", ""
	}
	var log strings.Builder
	fmt.Fprintf(&log, "strategy=exponential checkpoints then bisection; history_depth=%d probe_budget=%d\n", len(commits)-1, d.cfg.MaxLocalizationProbes)
	badIndex, probes := 0, 0 // commits are newest-to-oldest; index zero is the observed failing HEAD.
	distance := 1
	for distance < len(commits) && probes < d.cfg.MaxLocalizationProbes {
		if ctx.Err() != nil {
			return "", commits[badIndex], "", "inconclusive: cancelled during revision search", log.String()
		}
		passed, conclusive, took := d.probeCommit(ctx, commits[distance])
		probes++
		if !conclusive {
			fmt.Fprintf(&log, "probe %s: inconclusive duration=%s\n", shortSHA(commits[distance]), took)
			return "", commits[badIndex], "", "inconclusive: a revision probe timed out or failed to execute", log.String()
		}
		fmt.Fprintf(&log, "probe %s: passed=%t duration=%s\n", shortSHA(commits[distance]), passed, took)
		if passed {
			// Without an explicit --good endpoint this is a bounded history
			// walk, not a claim that the first transition was fully bisected.
			// Preserve the observed passing/failing endpoints and leave
			// BisectResult empty so callers do not present a walk as a bisect.
			return commits[distance], commits[badIndex], "", "confirmed", log.String()
		}
		badIndex = distance
		if distance == len(commits)-1 {
			break
		}
		distance *= 2
		if distance >= len(commits) {
			distance = len(commits) - 1
		}
	}
	return "", commits[badIndex], "", fmt.Sprintf("inconclusive: no passing revision found in %d adaptive probes", probes), log.String()
}

// bisectFromKnownEndpoints reuses the observed base/head outcomes and tests
// only intermediate first-parent commits. It stops after the configured probe
// budget, reporting a bounded interval when the exact boundary is unresolved.
func (d *Diagnoser) bisectFromKnownEndpoints(ctx context.Context, good, head string) (string, string, string, string, string) {
	commits := strings.Fields(strings.TrimSpace(gitOutput(d.cfg.RepoPath, "rev-list", "--first-parent", good+".."+head)))
	if len(commits) == 0 || commits[0] != head {
		return good, head, "", "inconclusive: base is not on the head's first-parent history", ""
	}
	var log strings.Builder
	fmt.Fprintf(&log, "strategy=base/head bracket bisection; intermediate_commits=%d probe_budget=%d\n", len(commits), d.cfg.MaxLocalizationProbes)
	lastGood, firstBad, result, status, bisectLog := d.bisectBracket(ctx, commits, 0, len(commits), good, 0, &log)
	// The configured endpoint is authoritative evidence for the last known
	// good revision. Intermediate passing probes narrow the boundary but do
	// not replace the endpoint in the report's public semantics.
	if result != "" || status == "confirmed" {
		lastGood = good
	}
	return lastGood, firstBad, result, status, bisectLog
}

// bisectBracket uses indexes into newest-to-oldest commits. badIndex is a
// known failure and goodIndex is a known pass; len(commits) represents a
// known passing revision older than every item in the slice.
func (d *Diagnoser) bisectBracket(ctx context.Context, commits []string, badIndex, goodIndex int, externalGood string, probes int, log *strings.Builder) (string, string, string, string, string) {
	if log == nil {
		log = &strings.Builder{}
	}
	for goodIndex-badIndex > 1 && probes < d.cfg.MaxLocalizationProbes {
		if ctx.Err() != nil {
			return boundaryGood(commits, goodIndex, externalGood), boundaryBad(commits, badIndex), "", "inconclusive: cancelled during revision search", log.String()
		}
		mid := badIndex + (goodIndex-badIndex)/2
		passed, conclusive, took := d.probeCommit(ctx, commits[mid])
		probes++
		if !conclusive {
			fmt.Fprintf(log, "probe %s: inconclusive duration=%s\n", shortSHA(commits[mid]), took)
			return boundaryGood(commits, goodIndex, externalGood), boundaryBad(commits, badIndex), "", "inconclusive: a revision probe timed out or failed to execute", log.String()
		}
		fmt.Fprintf(log, "probe %s: passed=%t duration=%s\n", shortSHA(commits[mid]), passed, took)
		if passed {
			goodIndex = mid
		} else {
			badIndex = mid
		}
	}
	good, bad := boundaryGood(commits, goodIndex, externalGood), boundaryBad(commits, badIndex)
	if goodIndex-badIndex == 1 {
		return good, bad, bad, "confirmed", log.String()
	}
	return good, bad, "", "probe budget exhausted: first-bad commit remains within the reported interval", log.String()
}

func boundaryGood(commits []string, index int, externalGood string) string {
	if index >= len(commits) {
		return externalGood
	}
	return commits[index]
}

func boundaryBad(commits []string, index int) string {
	if index < 0 || index >= len(commits) {
		return ""
	}
	return commits[index]
}

// bisect locates the first failing commit between a known-good and known-bad
// revision. It deliberately performs the binary search itself instead of
// parsing human-oriented `git bisect` output, which differs across Git
// versions and platforms.
func (d *Diagnoser) bisect(ctx context.Context, good, bad string) (string, string, string) {
	bisectCtx := ctx
	if budget := time.Duration(d.cfg.MaxCommits+2) * d.cfg.Timeout; budget > 0 {
		if budget > 30*time.Minute {
			budget = 30 * time.Minute
		}
		var cancel context.CancelFunc
		bisectCtx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}

	raw := strings.TrimSpace(gitOutput(d.cfg.RepoPath, "rev-list", "--first-parent", "--reverse", good+".."+bad))
	commits := strings.Fields(raw)
	if len(commits) == 0 {
		return "", "unavailable: no commits between known-good and known-bad revisions", raw
	}

	var log strings.Builder
	fmt.Fprintf(&log, "known good: %s\nknown bad: %s\n", good, bad)
	low, high := -1, len(commits)-1 // good is the virtual lower bound
	if !d.passesAt(bisectCtx, commits[high]) {
		fmt.Fprintf(&log, "bad endpoint %s: failed\n", commits[high])
	} else {
		return "", "unavailable: known-bad revision passes the recorded command", log.String()
	}
	for high-low > 1 {
		if bisectCtx.Err() != nil {
			return "", "cancelled", log.String()
		}
		mid := low + (high-low)/2
		passed := d.passesAt(bisectCtx, commits[mid])
		fmt.Fprintf(&log, "probe %s: passed=%t\n", commits[mid], passed)
		if passed {
			low = mid
		} else {
			high = mid
		}
	}
	return commits[high], "confirmed", log.String()
}

func (d *Diagnoser) diffScope(loc Localization) ([]string, []CommitInfo, string) {
	good, bad := loc.LastKnownGood, loc.FirstKnownBad
	if loc.BisectResult != "" {
		bad = loc.BisectResult
	}
	var rangeSpec string
	switch {
	case good != "" && bad != "":
		rangeSpec = good + ".." + bad
	case bad != "":
		rangeSpec = bad + "~1.." + bad
	default:
		return nil, nil, ""
	}

	files := strings.Fields(strings.TrimSpace(gitOutput(d.cfg.RepoPath, "diff", "--name-only", rangeSpec)))
	if len(files) > MaxListedFiles {
		files = files[:MaxListedFiles]
	}

	var commits []CommitInfo
	raw := strings.TrimSpace(gitOutput(d.cfg.RepoPath, "log", "--format=%H%x00%s", "--max-count=20", rangeSpec))
	for _, line := range strings.Split(raw, "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\x00", 2)
		info := CommitInfo{SHA: parts[0]}
		if len(parts) == 2 {
			info.Subject = parts[1]
		}
		commits = append(commits, info)
	}
	return files, commits, rangeSpec
}

var (
	fileRefPattern = regexp.MustCompile(`([A-Za-z0-9_./\-]+\.(?:go|py|rs|js|ts|tsx|jsx)):?\d*`)
	framePattern   = regexp.MustCompile(`(?m)(?:^\s*File "([^"]+)", line \d+, in ([A-Za-z0-9_.<>]+))|(?:\bin ([A-Za-z0-9_.<>]+)\()`)
)

// extractFrames pulls file and function mentions out of failing output. These
// are heuristic mentions and are labelled as such in the report.
func extractFrames(baseline Baseline) []string {
	seen := map[string]bool{}
	var frames []string
	for _, attempt := range baseline.Results {
		for _, match := range framePattern.FindAllStringSubmatch(attempt.Stderr, 20) {
			name := match[3]
			if name == "" {
				name = match[2]
			}
			if name == "" || seen[name] || len(frames) >= 20 {
				continue
			}
			seen[name] = true
			frames = append(frames, name)
		}
	}
	return frames
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func shellQuoteAll(args []string) []string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = shellQuote(arg)
	}
	return quoted
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// gitOutput runs git and returns its output, ignoring errors. Callers use it for
// optional context, never for a correctness decision.
func gitOutput(dir string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()
	out, err := gitRun(ctx, dir, args...)
	if err != nil {
		return out
	}
	return out
}

func gitRun(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
