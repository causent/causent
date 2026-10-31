package diagnosis

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BundleSchemaVersion is bumped whenever the on-disk bundle layout changes.
const BundleSchemaVersion = "cypher.diagnosis.bundle/v1"

// Manifest identifies a bundle and embeds the diagnosis it records. Replay reads
// this file and refuses to proceed when the bundle checksums do not match.
type Manifest struct {
	SchemaVersion string    `json:"schema_version"`
	BundleID      string    `json:"bundle_id"`
	CreatedAt     time.Time `json:"created_at"`
	EventCount    int       `json:"event_count"`
	Diagnosis     Report    `json:"diagnosis"`
}

// BisectResults is the localized git history recorded for replay and review.
type BisectResults struct {
	HeadCommit       string       `json:"head_commit"`
	LastKnownGood    string       `json:"last_known_good,omitempty"`
	FirstKnownBad    string       `json:"first_known_bad,omitempty"`
	BisectResult     string       `json:"bisect_result,omitempty"`
	BisectStatus     string       `json:"bisect_status"`
	BisectLog        string       `json:"bisect_log,omitempty"`
	CommitRange      string       `json:"commit_range,omitempty"`
	LikelyFiles      []string     `json:"likely_files,omitempty"`
	CandidateCommits []CommitInfo `json:"candidate_commits,omitempty"`
}

// WriteBundle writes a replayable diagnosis bundle and returns its directory.
// It is safe to call twice for the same directory: the second call refreshes the
// manifest, events, and checksums.
func WriteBundle(report Report, events []EventRecord, dir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("bundle directory is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(abs, "evidence"), 0o755); err != nil {
		return "", err
	}

	manifest := Manifest{
		SchemaVersion: BundleSchemaVersion,
		BundleID:      report.InvestigationID,
		CreatedAt:     time.Now().UTC(),
		EventCount:    len(events),
		Diagnosis:     report,
	}
	if err := writeJSONFile(filepath.Join(abs, "manifest.json"), manifest); err != nil {
		return "", err
	}
	if err := writeJSONFile(filepath.Join(abs, "environment.json"), report.Environment); err != nil {
		return "", err
	}
	if err := writeJSONFile(filepath.Join(abs, "baseline-results.json"), report.Baseline); err != nil {
		return "", err
	}
	bisect := BisectResults{
		HeadCommit:       report.Localization.HeadCommit,
		LastKnownGood:    report.Localization.LastKnownGood,
		FirstKnownBad:    report.Localization.FirstKnownBad,
		BisectResult:     report.Localization.BisectResult,
		BisectStatus:     report.Localization.BisectStatus,
		BisectLog:        report.Localization.BisectLog,
		CommitRange:      report.Localization.CommitRange,
		LikelyFiles:      report.Localization.LikelyFiles,
		CandidateCommits: report.Localization.CandidateCommit,
	}
	if err := writeJSONFile(filepath.Join(abs, "bisect-results.json"), bisect); err != nil {
		return "", err
	}
	if err := writeJSONFile(filepath.Join(abs, "report.json"), report); err != nil {
		return "", err
	}
	if err := writeEvents(filepath.Join(abs, "events.jsonl"), events); err != nil {
		return "", err
	}
	for _, item := range report.Evidence {
		name := sanitizeFilename(item.ID)
		if name == "" {
			continue
		}
		body := fmt.Sprintf("id: %s\nkind: %s\nsource: %s\ndigest: %s\n\n%s\n", item.ID, item.Kind, item.Source, item.Digest, item.Detail)
		if err := os.WriteFile(filepath.Join(abs, "evidence", name+".txt"), []byte(body), 0o644); err != nil {
			return "", err
		}
	}
	script := replayScript(report)
	if err := os.WriteFile(filepath.Join(abs, "replay.sh"), []byte(script), 0o755); err != nil {
		return "", err
	}
	if err := WriteChecksums(abs); err != nil {
		return "", err
	}
	return abs, nil
}

// ReadManifest loads and decodes a bundle manifest.
func ReadManifest(dir string) (Manifest, error) {
	var manifest Manifest
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("parse manifest: %w", err)
	}
	if manifest.SchemaVersion != BundleSchemaVersion {
		return manifest, fmt.Errorf("unsupported bundle schema %q", manifest.SchemaVersion)
	}
	return manifest, nil
}

// WriteChecksums hashes every bundle file except checksums.txt itself.
func WriteChecksums(dir string) error {
	files, err := bundleFiles(dir)
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, rel := range files {
		if rel == "checksums.txt" {
			continue
		}
		sum, err := fileDigest(filepath.Join(dir, rel))
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s  %s\n", sum, filepath.ToSlash(rel))
	}
	return os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(b.String()), 0o644)
}

// VerifyChecksums reports every file whose contents no longer match the bundle.
func VerifyChecksums(dir string) error {
	data, err := os.ReadFile(filepath.Join(dir, "checksums.txt"))
	if err != nil {
		return fmt.Errorf("read checksums: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	checked := 0
	var problems []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			problems = append(problems, "malformed checksum line: "+line)
			continue
		}
		expected, rel := parts[0], filepath.Clean(filepath.FromSlash(parts[1]))
		if filepath.IsAbs(rel) || strings.HasPrefix(rel, "..") {
			problems = append(problems, "checksum references a path outside the bundle: "+parts[1])
			continue
		}
		actual, err := fileDigest(filepath.Join(dir, rel))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", parts[1], err))
			continue
		}
		if actual != expected {
			problems = append(problems, fmt.Sprintf("%s: checksum mismatch", parts[1]))
		}
		checked++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if checked == 0 {
		return fmt.Errorf("checksums.txt lists no files")
	}
	if len(problems) > 0 {
		return fmt.Errorf("bundle integrity check failed: %s", strings.Join(problems, "; "))
	}
	return nil
}

func bundleFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files = append(files, rel)
		return nil
	})
	sort.Strings(files)
	return files, err
}

func fileDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func writeJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func writeEvents(path string, events []EventRecord) error {
	var b strings.Builder
	for _, ev := range events {
		line, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func sanitizeFilename(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), ".-")
}

// replayScript is a convenience entry point for humans. `cypher replay` performs
// the authoritative re-run, including checksum verification.
func replayScript(report Report) string {
	repo := report.RepoPath
	if report.Environment.RepoPath != "" {
		repo = report.Environment.RepoPath
	}
	commit := report.Environment.HeadCommit
	if commit == "" {
		commit = report.Localization.HeadCommit
	}
	command := "true"
	if len(report.Baseline.Command) > 0 {
		command = strings.Join(shellQuoteAll(report.Baseline.Command), " ")
	}
	return fmt.Sprintf(`#!/bin/sh
# Generated by cypher diagnose for bundle %s.
# Re-runs the recorded command at the recorded commit in a throwaway worktree.
# This is a reproduction script, not a fix and not a verification of a fix.
set -eu
REPO="${1:-}"
if [ -z "$REPO" ]; then REPO=%s; fi
COMMIT=%s
WORKDIR="$(mktemp -d)"
cleanup() { git -C "$REPO" worktree remove --force "$WORKDIR" >/dev/null 2>&1 || rm -rf "$WORKDIR"; }
trap cleanup EXIT INT TERM
git -C "$REPO" worktree add --detach "$WORKDIR" "$COMMIT" >/dev/null
cd "$WORKDIR"
%s
`, report.InvestigationID, shellQuote(repo), shellQuote(commit), command)
}
