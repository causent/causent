package diagnosis

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	dir, err := os.MkdirTemp("", "cypher-workspace-*")
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

func (d *Diagnoser) localize(ctx context.Context, workspace string, baseline Baseline) (Localization, []EvidenceItem, error) {
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
		if !d.passesAt(ctx, good) {
			return loc, evidence, fmt.Errorf("known-good revision %q does not pass the recorded command", d.cfg.GoodRef)
		}
		loc.LastKnownGood = good
		firstBad, status, log := d.bisect(ctx, good, loc.HeadCommit)
		loc.BisectStatus = status
		loc.BisectLog = bound(log, MaxEvidenceExcerpt)
		if firstBad != "" {
			loc.BisectResult = firstBad
			loc.FirstKnownBad = firstBad
		} else {
			loc.FirstKnownBad = loc.HeadCommit
		}
	} else {
		loc.LastKnownGood, loc.FirstKnownBad, loc.BisectStatus = d.walk(ctx, loc.HeadCommit)
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
	if loc.BisectResult != "" {
		evidence = append(evidence, EvidenceItem{
			ID:     "E-git-bisect",
			Kind:   "git_bisect",
			Source: "git bisect run",
			Digest: digestString(loc.BisectLog),
			Detail: fmt.Sprintf("first bad commit from bisect: %s\n%s", loc.BisectResult, bound(loc.BisectLog, MaxEvidenceExcerpt)),
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

// walk searches backwards from HEAD for the newest commit where the command
// passes. It is bounded by MaxCommits.
func (d *Diagnoser) walk(ctx context.Context, head string) (string, string, string) {
	out := strings.TrimSpace(gitOutput(d.cfg.RepoPath, "rev-list", "--first-parent", fmt.Sprintf("--max-count=%d", d.cfg.MaxCommits), head))
	if out == "" {
		return "", "", "unavailable: no commits in range"
	}
	commits := strings.Fields(out)
	for i, commit := range commits {
		if ctx.Err() != nil {
			return "", "", "cancelled"
		}
		// HEAD is known bad; only inspect ancestors.
		if i == 0 {
			continue
		}
		if d.passesAt(ctx, commit) {
			firstBad := ""
			if i-1 >= 0 {
				firstBad = commits[i-1]
			}
			return commit, firstBad, "not_needed: last-good and first-bad are adjacent in the walked history"
		}
	}
	return "", "", fmt.Sprintf("unavailable: no passing commit in the last %d commits", d.cfg.MaxCommits)
}

// bisect runs `git bisect run` between a known-good and known-bad commit.
func (d *Diagnoser) bisect(ctx context.Context, good, bad string) (string, string, string) {
	dir, cleanup, err := isolatedWorkspace(ctx, d.cfg.RepoPath, bad)
	if err != nil {
		return "", "unavailable: " + err.Error(), ""
	}
	defer cleanup()

	script := filepath.Join(os.TempDir(), "cypher-bisect-"+strings.TrimPrefix(newID(), ".")+".sh")
	body := "#!/bin/sh\n" + strings.Join(shellQuoteAll(d.cfg.Command), " ") + "\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		return "", "unavailable: " + err.Error(), ""
	}
	defer os.Remove(script)

	budget := time.Duration(d.cfg.MaxCommits+2) * d.cfg.Timeout
	if budget <= 0 || budget > 30*time.Minute {
		budget = 30 * time.Minute
	}
	bisectCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var log strings.Builder
	steps := [][]string{
		{"bisect", "start"},
		{"bisect", "bad", bad},
		{"bisect", "good", good},
		{"bisect", "run", script},
	}
	for _, step := range steps {
		out, err := gitRun(bisectCtx, dir, step...)
		log.WriteString("$ git " + strings.Join(step, " ") + "\n" + bound(out, 2000) + "\n")
		if err != nil && step[0] == "bisect" && len(step) > 1 && step[1] == "run" {
			// bisect run exits non-zero when it finds the first bad commit.
			log.WriteString("exit: " + err.Error() + "\n")
		}
	}
	_, _ = gitRun(context.Background(), dir, "bisect", "reset")

	text := log.String()
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "is the first bad commit") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				return strings.TrimSpace(fields[0]), "confirmed", text
			}
		}
	}
	return "", "unavailable: bisect did not identify a first bad commit", text
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
