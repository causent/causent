package diagnosis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/localization"
)

var (
	pythonFrame        = regexp.MustCompile(`File "([^"]+)", line ([0-9]+)`)
	goFrame            = regexp.MustCompile(`([^\s()]+\.go):([0-9]+)`)
	failureLine        = regexp.MustCompile(`(?m)^--- FAIL: ([^ (]+)`)
	genericFailureLine = regexp.MustCompile(`(?m)^FAIL\s+([^ (]+)`)
	pytestFailure      = regexp.MustCompile(`(?m)^FAILED\s+([^\s]+)(?:\s+-\s*(.*))?$`)
	jestFailure        = regexp.MustCompile(`(?m)^\s*[●•]\s+(.+)$`)
)

type failureObservation struct {
	Test    string
	Message string
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
	for _, match := range genericFailureLine.FindAllStringSubmatch(text, -1) {
		add(match[1], match[1])
	}
	for _, match := range pytestFailure.FindAllStringSubmatch(text, -1) {
		add(match[1], match[2])
	}
	for _, match := range jestFailure.FindAllStringSubmatch(text, -1) {
		add(match[1], match[1])
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
		if item.Kind != "original_ci_log" && item.Kind != "junit_report" {
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
func failureText(b Baseline) string {
	var bld strings.Builder
	for _, a := range b.Results {
		bld.WriteString(a.Stderr)
		bld.WriteByte('\n')
	}
	return bld.String()
}
func architectureFrames(b Baseline, failures []domain.FailureEpisode) []localization.Frame {
	var out []localization.Frame
	for _, a := range b.Results {
		text := a.Stderr
		failureIDs := failureIDsForText(a.Stderr, failures)
		for _, m := range pythonFrame.FindAllStringSubmatch(text, -1) {
			out = append(out, localization.Frame{File: m[1], Line: atoi(m[2]), FailureIDs: failureIDs})
		}
		for _, m := range goFrame.FindAllStringSubmatch(text, -1) {
			out = append(out, localization.Frame{File: m[1], Line: atoi(m[2]), FailureIDs: failureIDs})
		}
	}
	return out
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
