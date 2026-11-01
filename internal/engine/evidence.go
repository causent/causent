package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/causent/causent/internal/domain"
)

type StackFrame struct {
	File     string
	Line     int
	Function string
	Source   string
	CallSite string
}

var pythonFrameRE = regexp.MustCompile(`^\s*File "([^"]+)", line ([0-9]+), in (.+)$`)

// ParsePythonStackTrace extracts Python traceback frames without executing
// anything or trusting paths outside the repository.
func ParsePythonStackTrace(trace string) []StackFrame {
	var frames []StackFrame
	for _, line := range strings.Split(trace, "\n") {
		m := pythonFrameRE.FindStringSubmatch(line)
		if len(m) != 4 {
			continue
		}
		n, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		frames = append(frames, StackFrame{File: m[1], Line: n, Function: strings.TrimSpace(m[3])})
	}
	return frames
}

func enrichFrames(repo string, frames []StackFrame) []StackFrame {
	for idx := range frames {
		path, ok := repoFile(repo, frames[idx].File)
		if !ok {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		start, end := frames[idx].Line-3, frames[idx].Line+2
		if start < 0 {
			start = 0
		}
		if end > len(lines) {
			end = len(lines)
		}
		frames[idx].Source = strings.Join(lines[start:end], "\n")
		if frames[idx].Line > 0 && frames[idx].Line <= len(lines) {
			frames[idx].CallSite = strings.TrimSpace(lines[frames[idx].Line-1])
		}
	}
	return frames
}

func repoFile(repo, candidate string) (string, bool) {
	clean := filepath.Clean(candidate)
	if filepath.IsAbs(clean) {
		rel, err := filepath.Rel(repo, clean)
		if err != nil || strings.HasPrefix(rel, "..") {
			return "", false
		}
		clean = rel
	}
	if clean == "." || strings.HasPrefix(clean, "..") {
		return "", false
	}
	full := filepath.Join(repo, clean)
	info, err := os.Stat(full)
	return full, err == nil && !info.IsDir()
}

func collectPythonTests(repo string, frames []StackFrame) string {
	var roots []string
	for _, frame := range frames {
		if strings.HasSuffix(frame.File, ".py") {
			roots = append(roots, frame.File)
		}
	}
	var b strings.Builder
	seen := map[string]bool{}
	for _, root := range roots {
		base := filepath.Base(root)
		if !strings.HasPrefix(base, "test_") && !strings.HasSuffix(base, "_test.py") {
			continue
		}
		if seen[root] {
			continue
		}
		seen[root] = true
		path, ok := repoFile(repo, root)
		if !ok {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		b.WriteString(fmt.Sprintf("TEST %s\n%s\n", root, bounded(string(data), 6000)))
	}
	// Fixture names are useful even when the traceback points into application
	// code. Only names are collected here; contents remain bounded and local.
	var fixtures []string
	_ = filepath.WalkDir(repo, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || len(fixtures) >= 20 {
			return nil
		}
		name := strings.ToLower(entry.Name())
		if strings.Contains(name, "fixture") || strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			if rel, e := filepath.Rel(repo, path); e == nil && !strings.HasPrefix(rel, ".git") {
				fixtures = append(fixtures, rel)
			}
		}
		return nil
	})
	if len(fixtures) > 0 {
		b.WriteString("FIXTURES\n")
		b.WriteString(strings.Join(fixtures, "\n"))
	}
	return b.String()
}

func (i *Investigator) collectEvidenceM4(ctx context.Context, inv domain.Investigation, repo string, command []string, rep domain.Reproduction) ([]domain.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, &domain.CancellationError{}
	}
	rawTrace := rep.Result.Stderr + "\n" + rep.Result.Stdout
	frames := enrichFrames(repo, ParsePythonStackTrace(rawTrace))
	stack := bounded(rawTrace, 12000)
	if len(frames) > 0 {
		stack += "\nFRAMES\n"
		for _, frame := range frames {
			stack += fmt.Sprintf("%s:%d in %s\nCALLSITE: %s\nSOURCE:\n%s\n", frame.File, frame.Line, frame.Function, frame.CallSite, bounded(frame.Source, 1500))
		}
	}
	tests := collectPythonTests(repo, frames)
	gitEvidence, err := gitEvidence(ctx, repo)
	if err != nil {
		// A test may provide a repository-shaped directory without a complete
		// Git checkout; preserve that limitation as evidence rather than
		// discarding the reproducible failure.
		gitEvidence = "git evidence unavailable: " + err.Error()
	}
	items := []struct {
		typ, source, ref, payload string
	}{
		{string(domain.EvidenceStackTrace), "python_traceback", "traceback", stack},
		{string(domain.EvidenceSourceCode), "traceback_frames", "source_context", stack},
		{string(domain.EvidenceGitDiff), "git", "git_state", gitEvidence},
		{string(domain.EvidenceSourceCode), "tests_and_fixtures", "test_fixture_context", tests},
	}
	var evidence []domain.Evidence
	for _, item := range items {
		if strings.TrimSpace(item.payload) == "" {
			continue
		}
		ev := domain.Evidence{ID: newID(), InvestigationID: inv.ID, Type: domain.EvidenceType(item.typ), Source: item.source, Timestamp: time.Now().UTC(), ContentRef: item.ref, Digest: digestString(item.payload), Payload: item.payload, Provenance: fmt.Sprintf("repo=%s command=%q", repo, command)}
		i.attachArtifact(&ev)
		if err := i.Store.SaveEvidence(ev); err != nil {
			return nil, fmt.Errorf("save evidence %s: %w", item.source, err)
		}
		evidence = append(evidence, ev)
	}
	return evidence, nil
}

func gitEvidence(ctx context.Context, repo string) (string, error) {
	run := func(args ...string) (string, error) {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(c, "git", args...)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return strings.TrimSpace(string(out)), nil
	}
	head, err := run("rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	status, err := run("status", "--short")
	if err != nil {
		return "", err
	}
	diff, err := run("diff", "--", ".")
	if err != nil {
		return "", err
	}
	return bounded(fmt.Sprintf("HEAD %s\nSTATUS\n%s\nDIFF\n%s", head, status, diff), 12000), nil
}

func bounded(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n... [bounded]"
}
