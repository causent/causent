package diagnosis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/localization"
)

var (
	pythonFrame        = regexp.MustCompile(`File "([^"]+)", line ([0-9]+)`)
	goFrame            = regexp.MustCompile(`([^\s()]+\.go):([0-9]+)`)
	failureLine        = regexp.MustCompile(`(?m)^--- FAIL:\s+(.+?)(?:\s+\([0-9.]+s\))?\s*$`)
	goFailureLine      = regexp.MustCompile(`(?m)^=== FAIL:\s+(.+?)(?:\s+\([0-9.]+s\))?\s*$`)
	genericFailureLine = regexp.MustCompile(`(?m)^FAIL\s+([^ (]+)`)
	pytestFailure      = regexp.MustCompile(`(?m)^FAILED\s+([^\s]+)(?:\s+-\s*(.*))?$`)
	jestFailure        = regexp.MustCompile(`(?m)^\s*[●•]\s+(.+)$`)
	raceFailure        = regexp.MustCompile(`(?m)^WARNING: DATA RACE\s*$`)
)

type failureObservation struct {
	Test    string
	Message string
}

func isCIEvidenceKind(kind string) bool {
	return kind == "ci_log" || kind == "original_ci_log" || kind == "junit_report" || kind == "junit_xml" || kind == "ci_artifact"
}

func externalFailureEvidence(items []EvidenceItem) bool {
	for _, item := range items {
		if !isCIEvidenceKind(item.Kind) {
			continue
		}
		if len(parseFailureObservations(item.Detail)) > 0 {
			return true
		}
	}
	return false
}

func artifactEvidenceAttempts(items []EvidenceItem) []Attempt {
	var attempts []Attempt
	for _, item := range items {
		if !isCIEvidenceKind(item.Kind) {
			continue
		}
		if len(parseFailureObservations(item.Detail)) == 0 {
			continue
		}
		attempts = append(attempts, Attempt{
			Index:    len(attempts),
			ExitCode: 1,
			Executed: true,
			Stderr:   bound(item.Detail, MaxEvidenceExcerpt),
		})
	}
	return attempts
}

func artifactBaseline(command []string, items []EvidenceItem) Baseline {
	attempts := artifactEvidenceAttempts(items)
	return Baseline{
		Attempts: len(attempts),
		Failures: len(attempts),
		Results:  attempts,
		Command:  command,
		Source:   "ci_artifact",
	}
}

func artifactClassificationEvidence(class Classification, baseline Baseline) EvidenceItem {
	detail := fmt.Sprintf("classification=%s failures=%d source=%s; this is CI artifact evidence, not a local reproduction", class, baseline.Failures, baseline.Source)
	sum := sha256.Sum256([]byte(detail))
	return EvidenceItem{
		ID:         "E-classification",
		Kind:       "ci_artifact_observation",
		Source:     "normalized CI artifacts",
		Digest:     hex.EncodeToString(sum[:]),
		Detail:     detail,
		Provenance: "normalized existing CI evidence",
	}
}

// parseFailureObservations extracts multiple test failures from one CI log.
// It is intentionally parser-shaped rather than a root-cause classifier.
func parseFailureObservations(text string) []failureObservation {
	seen := map[string]bool{}
	var out []failureObservation
	add := func(test, message string) {
		test, message = strings.TrimSpace(test), strings.TrimSpace(message)
		if test == "" {
			return
		}
		if message == "" {
			message = test
		}
		key := test + "\x00" + message
		if !seen[key] {
			seen[key] = true
			out = append(out, failureObservation{Test: test, Message: message})
		}
	}
	for _, match := range failureLine.FindAllStringSubmatch(text, -1) {
		add(match[1], match[1])
	}
	for _, match := range goFailureLine.FindAllStringSubmatch(text, -1) {
		add(match[1], match[1])
	}
	for _, match := range genericFailureLine.FindAllStringSubmatch(text, -1) {
		add(match[1], match[1])
	}
	for _, match := range pytestFailure.FindAllStringSubmatch(text, -1) {
		add(match[1], match[2])
	}
	for _, match := range jestFailure.FindAllStringSubmatch(text, -1) {
		add(match[1], match[1])
	}
	if raceFailure.MatchString(text) {
		add("race detector", "Go race detector reported DATA RACE")
	}
	if strings.Contains(text, "<testsuite") || strings.Contains(text, "<testsuites") {
		if junit, err := parseJUnitFailures(text); err == nil {
			for _, observation := range junit {
				add(observation.Test, observation.Message)
			}
		}
	}
	return out
}

// persistArchitecture is implemented in pipeline.go as a staged, demand-driven path.

func (d *Diagnoser) persistReportEvidence(report *Report) error {
	if d.cfg.Store == nil {
		return nil
	}
	for _, item := range report.Evidence {
		if err := d.cfg.Store.SaveEvidence(domain.Evidence{ID: domain.ID(item.ID), InvestigationID: domain.ID(report.InvestigationID), Type: domain.EvidenceType(item.Kind), Source: item.Source, Timestamp: report.CreatedAt, ContentRef: item.Kind, Digest: item.Digest, Payload: item.Detail, Provenance: "diagnosis report evidence"}); err != nil {
			return err
		}
	}
	return nil
}

func (d *Diagnoser) persistFailureEpisodes(report *Report, executionID string, baseline Baseline) ([]domain.FailureEpisode, error) {
	seen := map[string]bool{}
	var episodes []domain.FailureEpisode
	for _, attempt := range baseline.Results {
		if !attempt.Failed() {
			continue
		}
		observations := parseFailureObservations(attempt.Stderr)
		if len(observations) == 0 {
			observations = []failureObservation{{Message: failureSignature(attempt.Stderr)}}
		}
		for _, observation := range observations {
			sig := observation.Message
			if sig == "" {
				sig = "exit_code:" + fmt.Sprint(attempt.ExitCode)
			}
			if seen[sig] {
				continue
			}
			seen[sig] = true
			sum := sha256.Sum256([]byte(report.InvestigationID + sig))
			id := "failure:" + hex.EncodeToString(sum[:8])
			episode := domain.FailureEpisode{ID: id, ExecutionID: executionID, TestIdentifier: observation.Test, FailureMessage: sig, FailureType: string(report.Classification), Status: "observed"}
			episodes = append(episodes, episode)
			if d.cfg.Store != nil {
				if err := d.cfg.Store.SaveFailureEpisode(episode); err != nil {
					return nil, err
				}
			}
		}
	}
	// CI logs often contain failures from several jobs/tests but are not part
	// of reproduction attempts. Treat them as observations, never as reruns.
	for _, item := range report.Evidence {
		if !isCIEvidenceKind(item.Kind) {
			continue
		}
		for _, observation := range parseFailureObservations(item.Detail) {
			if seen[observation.Message] {
				continue
			}
			seen[observation.Message] = true
			sum := sha256.Sum256([]byte(report.InvestigationID + observation.Message))
			episode := domain.FailureEpisode{ID: "failure:" + hex.EncodeToString(sum[:8]), ExecutionID: executionID, TestIdentifier: observation.Test, FailureMessage: observation.Message, FailureType: string(report.Classification), Status: "observed_from_ci_artifact"}
			episodes = append(episodes, episode)
			if d.cfg.Store != nil {
				if err := d.cfg.Store.SaveFailureEpisode(episode); err != nil {
					return nil, err
				}
			}
		}
	}
	return episodes, nil
}

func evidenceIDsToStrings(ids []domain.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, string(id))
	}
	return out
}

func evidenceIDsOfHistorical(values []domain.Evidence) []domain.ID {
	out := make([]domain.ID, 0, len(values))
	for _, value := range values {
		out = append(out, value.ID)
	}
	return out
}
func failureSignature(text string) string {
	if m := failureLine.FindStringSubmatch(text); len(m) > 1 {
		return m[1]
	}
	if m := genericFailureLine.FindStringSubmatch(text); len(m) > 1 {
		return m[1]
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > 0 {
		return lines[len(lines)-1]
	}
	return ""
}
func failureText(b Baseline, evidence []EvidenceItem) string {
	var bld strings.Builder
	for _, a := range b.Results {
		bld.WriteString(a.Stderr)
		bld.WriteByte('\n')
	}
	for _, item := range evidence {
		if isCIEvidenceKind(item.Kind) {
			bld.WriteString(item.Detail)
			bld.WriteByte('\n')
		}
	}
	return bld.String()
}
func architectureFrames(b Baseline, failures []domain.FailureEpisode, evidence []EvidenceItem) []localization.Frame {
	var out []localization.Frame
	seen := map[string]bool{}
	failureIDs := make([]string, 0, len(failures))
	for _, failure := range failures {
		failureIDs = append(failureIDs, failure.ID)
	}
	addFrames := func(text string) {
		for _, m := range pythonFrame.FindAllStringSubmatch(text, -1) {
			addFrame(&out, seen, normalizeEvidencePath(m[1]), atoi(m[2]), failureIDs)
		}
		for _, m := range goFrame.FindAllStringSubmatch(text, -1) {
			addFrame(&out, seen, normalizeEvidencePath(m[1]), atoi(m[2]), failureIDs)
		}
	}
	for _, a := range b.Results {
		text := a.Stderr
		failureIDs := failureIDsForText(a.Stderr, failures)
		for _, m := range pythonFrame.FindAllStringSubmatch(text, -1) {
			addFrame(&out, seen, normalizeEvidencePath(m[1]), atoi(m[2]), failureIDs)
		}
		for _, m := range goFrame.FindAllStringSubmatch(text, -1) {
			addFrame(&out, seen, normalizeEvidencePath(m[1]), atoi(m[2]), failureIDs)
		}
	}
	for _, item := range evidence {
		if isCIEvidenceKind(item.Kind) {
			addFrames(item.Detail)
		}
	}
	return out
}

func addFrame(out *[]localization.Frame, seen map[string]bool, file string, line int, failureIDs []string) {
	if file == "" || line <= 0 {
		return
	}
	key := fmt.Sprintf("%s:%d", file, line)
	if seen[key] {
		return
	}
	seen[key] = true
	*out = append(*out, localization.Frame{File: file, Line: line, FailureIDs: failureIDs})
}

func normalizeEvidencePath(path string) string {
	path = filepath.ToSlash(strings.TrimSpace(path))
	if strings.HasPrefix(path, "/usr/local/go/") || strings.HasPrefix(path, "/usr/lib/go/") {
		return ""
	}
	if marker := "/kubernetes/"; strings.Contains(path, marker) {
		path = path[strings.Index(path, marker)+len(marker):]
	}
	return strings.TrimPrefix(path, "./")
}

// observedFilesFromEvidence returns source paths reported by CI diagnostics.
// These are observations from the tool output; repository indexing later
// resolves them against the checked-out revision before treating them as
// source candidates.
func observedFilesFromEvidence(b Baseline, evidence []EvidenceItem) []string {
	frames := architectureFrames(b, nil, evidence)
	seen := map[string]bool{}
	var files []string
	for _, frame := range frames {
		path := filepath.ToSlash(filepath.Clean(strings.TrimPrefix(frame.File, "./")))
		if path == "." || path == "" || seen[path] {
			continue
		}
		seen[path] = true
		files = append(files, path)
	}
	return files
}

func containsPath(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// sourceEvidenceForCandidates reads only bounded excerpts from the checked-out
// revision. It turns a parser-derived location into independently inspected
// source evidence without pretending that the excerpt proves causality.
func sourceEvidenceForCandidates(workspace, revision string, candidates []domain.CandidateLocation) ([]domain.CandidateLocation, []EvidenceItem) {
	if workspace == "" {
		return candidates, nil
	}
	seen := map[string]bool{}
	evidenceByCandidate := map[string]EvidenceItem{}
	for _, candidate := range candidates {
		path := filepath.FromSlash(candidate.Location.FilePath)
		if path == "" || filepath.IsAbs(path) || strings.HasPrefix(filepath.Clean(path), ".."+string(filepath.Separator)) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(workspace, path))
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		line := candidate.Location.StartLine
		if line < 1 || line > len(lines) {
			continue
		}
		start := line - 3
		if start < 1 {
			start = 1
		}
		end := line + 3
		if end > len(lines) {
			end = len(lines)
		}
		var excerpt strings.Builder
		for current := start; current <= end; current++ {
			fmt.Fprintf(&excerpt, "%d| %s\n", current, lines[current-1])
		}
		key := candidate.Location.FilePath + ":" + fmt.Sprint(line)
		if seen[key] {
			continue
		}
		seen[key] = true
		detail := fmt.Sprintf("checked-out revision %s\n%s", revision, bound(excerpt.String(), MaxEvidenceExcerpt))
		evidenceByCandidate[candidate.ID] = EvidenceItem{
			ID:         "E-source-" + digestString(revision + "\x00" + key)[:12],
			Kind:       "source_excerpt",
			Source:     candidate.Location.FilePath,
			Digest:     digestString(detail),
			Detail:     detail,
			Provenance: "deterministic inspection of the checked-out revision",
			Revision:   revision,
		}
	}
	var evidence []EvidenceItem
	for i := range candidates {
		if item, ok := evidenceByCandidate[candidates[i].ID]; ok {
			candidates[i].SupportingEvidenceIDs = appendUnique(candidates[i].SupportingEvidenceIDs, domain.ID(item.ID))
			evidence = append(evidence, item)
		}
	}
	return candidates, evidence
}

func failureIDsForText(text string, failures []domain.FailureEpisode) []string {
	var out []string
	for _, failure := range failures {
		if strings.Contains(text, failure.FailureMessage) || strings.Contains(text, failure.TestIdentifier) {
			out = append(out, failure.ID)
		}
	}
	return out
}
func atoi(v string) int {
	var n int
	for _, r := range v {
		if r >= '0' && r <= '9' {
			n = n*10 + int(r-'0')
		}
	}
	return n
}
