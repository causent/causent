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
	"github.com/causent/malenia/internal/persistence"
)

var (
	pythonFrame        = regexp.MustCompile(`File "([^"]+)", line ([0-9]+)`)
	goFrame            = regexp.MustCompile(`([^\s()]+\.go):([0-9]+)`)
	failureLine        = regexp.MustCompile(`(?m)^--- FAIL:\s+(.+?)(?:\s+\([0-9.]+s\))?\s*$`)
	goFailureLine      = regexp.MustCompile(`(?m)^=== FAIL:\s+(.+?)(?:\s+\([0-9.]+s\))?\s*$`)
	genericFailureLine = regexp.MustCompile(`(?m)^FAIL\s+([^ (]+)`)
	pytestFailure      = regexp.MustCompile(`(?m)^FAILED\s+([^\s]+)(?:\s+-\s*(.*))?$`)
	jestFailure        = regexp.MustCompile(`(?m)^\s*[●•]\s+(.+)$`)
	tapFailure         = regexp.MustCompile(`(?m)^\s*not ok\b(?:\s+[0-9]+)?(?:\s+-\s+)?([^\r\n]*)`)
	runtimeException   = regexp.MustCompile(`(?m)(?:Traceback \(most recent call last\):|^panic:|Exception in thread |^[A-Za-z0-9_$.]+(?:Error|Exception|Failure):)`)
	buildDiagnostic    = regexp.MustCompile(`(?m)^(?:[^\r\n:]+:)?[^\r\n]*:[0-9]+(?::[0-9]+)?:\s*(?:fatal\s+)?(?:error\b|undefined:|cannot find|undeclared|no required module)|^error(?:\[[^\r\n\]]+\])?:\s+`)
	testReportFailure  = regexp.MustCompile(`(?i)<(?:failure|error)\b`)
	raceFailure        = regexp.MustCompile(`(?m)^WARNING: DATA RACE\s*$`)
	raceFunction       = regexp.MustCompile(`^\s*(.+?\([^)]*\))(?:\s+\+0x[0-9a-fA-F]+)?\s*$`)
	raceTestLine       = regexp.MustCompile(`^=== (?:RUN|PAUSE|CONT)\s+(.+)$`)
	raceLocationLine   = regexp.MustCompile(`^\s+([^\s()]+\.go):([0-9]+)\s+\+0x[0-9a-fA-F]+`)
	raceAccessHeader   = regexp.MustCompile(`(?i)^(?:Previous )?(read|write) at (0x[0-9a-fA-F]+)?(?: by goroutine ([0-9]+))?`)
	raceCreationHeader = regexp.MustCompile(`(?i)^Goroutine ([0-9]+) .*created at:`)
)

type failureObservation struct {
	Test    string
	Message string
}

func parseRaceReports(text string) []RaceReport {
	if !raceFailure.MatchString(text) {
		return nil
	}
	var reports []RaceReport
	lines := strings.Split(text, "\n")
	current := RaceReport{}
	section := ""
	currentTest := ""
	pendingFunction := ""
	currentCreationGoroutine := int64(0)
	flush := func() {
		if current.Test == "" {
			current.Test = currentTest
		}
		if current.ReadAccessType != "" || current.WriteAccessType != "" || len(current.ReadStack) > 0 || len(current.WriteStack) > 0 {
			reports = append(reports, current)
		}
		current = RaceReport{}
		section = ""
		currentCreationGoroutine = 0
	}
	for lineNumber, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case raceTestLine.MatchString(trimmed):
			currentTest = strings.TrimSpace(raceTestLine.FindStringSubmatch(trimmed)[1])
		case strings.HasPrefix(trimmed, "WARNING: DATA RACE"):
			flush()
		case strings.HasPrefix(trimmed, "Previous read at"), strings.HasPrefix(trimmed, "Read at"):
			section = "read"
			pendingFunction = ""
			current.ReadAccessType = "read"
			if match := raceAccessHeader.FindStringSubmatch(trimmed); len(match) > 1 {
				current.ReadAddress = match[2]
				if len(match) > 3 && match[3] != "" {
					current.ReadGoroutineID = int64(atoi(match[3]))
				}
			}
		case strings.HasPrefix(trimmed, "Previous write at"), strings.HasPrefix(trimmed, "Write at"):
			section = "write"
			pendingFunction = ""
			current.WriteAccessType = "write"
			if match := raceAccessHeader.FindStringSubmatch(trimmed); len(match) > 1 {
				current.WriteAddress = match[2]
				if len(match) > 3 && match[3] != "" {
					current.WriteGoroutineID = int64(atoi(match[3]))
				}
			}
		case strings.Contains(trimmed, " created at:"):
			section = "create"
			pendingFunction = ""
			if match := raceCreationHeader.FindStringSubmatch(trimmed); len(match) > 1 {
				currentCreationGoroutine = int64(atoi(match[1]))
				if current.GoroutineCreationStacksByGoroutine == nil {
					current.GoroutineCreationStacksByGoroutine = map[int64][]localization.Frame{}
				}
			}
			current.GoroutineCreationStacks = append(current.GoroutineCreationStacks, nil)
		case strings.HasPrefix(trimmed, "================") || strings.HasPrefix(trimmed, "--- FAIL:"):
			section = ""
			pendingFunction = ""
		case strings.HasPrefix(trimmed, "=== FAIL:") || strings.HasPrefix(trimmed, "=== SKIP:"):
			section = ""
			pendingFunction = ""
		case trimmed == "":
			// Race stack sections are separated by blank lines. This prevents
			// later test/log output from being interpreted as stack frames.
			section = ""
			pendingFunction = ""
		default:
			m := raceLocationLine.FindStringSubmatch(line)
			if len(m) == 0 {
				if fn := raceFunction.FindStringSubmatch(trimmed); len(fn) > 1 && section != "" && !strings.Contains(trimmed, "Goroutine ") {
					pendingFunction = fn[1]
				} else if trimmed != "" {
					pendingFunction = ""
				}
				continue
			}
			if pendingFunction == "" {
				continue
			}
			frame := localization.Frame{File: normalizeRacePath(m[1]), Line: atoi(m[2]), Function: pendingFunction, LogLine: lineNumber + 1, Provenance: "direct_stack_frame"}
			if frame.File == "" {
				continue
			}
			pendingFunction = ""
			switch section {
			case "read":
				if isRaceInstrumentationFrame(frame) {
					continue
				}
				current.ReadFrameRole = raceFrameRole(frame)
				current.ReadStack = append(current.ReadStack, frame)
			case "write":
				if isRaceInstrumentationFrame(frame) {
					continue
				}
				current.WriteFrameRole = raceFrameRole(frame)
				current.WriteStack = append(current.WriteStack, frame)
			case "create":
				if len(current.GoroutineCreationStacks) == 0 {
					current.GoroutineCreationStacks = append(current.GoroutineCreationStacks, nil)
				}
				last := len(current.GoroutineCreationStacks) - 1
				current.GoroutineCreationStacks[last] = append(current.GoroutineCreationStacks[last], frame)
				if currentCreationGoroutine != 0 {
					current.GoroutineCreationStacksByGoroutine[currentCreationGoroutine] = append(current.GoroutineCreationStacksByGoroutine[currentCreationGoroutine], frame)
				}
			}
		}
	}
	flush()
	return reports
}

func isRaceInstrumentationFrame(frame localization.Frame) bool {
	return frame.Function == "runtime.racewrite()" || frame.Function == "runtime.raceread()" || frame.File == "<autogenerated>"
}

func raceFrameRole(frame localization.Frame) string {
	if strings.Contains(frame.Function, ".gowrap") || strings.HasSuffix(frame.Function, ".func1()") {
		return "goroutine_creation_or_wrapper"
	}
	return "enclosing_source_frame"
}

func buildFailureIncidents(report *Report) []FailureIncident {
	var incidents []FailureIncident
	seenRace := map[string]bool{}
	for index, race := range report.RaceReports {
		readKey, writeKey := "", ""
		if len(race.ReadStack) > 0 {
			readKey = fmt.Sprintf("%s:%d", race.ReadStack[0].File, race.ReadStack[0].Line)
		}
		if len(race.WriteStack) > 0 {
			writeKey = fmt.Sprintf("%s:%d", race.WriteStack[0].File, race.WriteStack[0].Line)
		}
		raceKey := race.Test + "\x00" + readKey + "\x00" + writeKey
		if seenRace[raceKey] {
			continue
		}
		seenRace[raceKey] = true
		tests := []string{}
		for _, episode := range report.FailureEpisodes {
			test := episode.TestIdentifier
			if pos := strings.Index(test, "TestWatch"); pos >= 0 {
				test = test[pos:]
			}
			if test == "" || test == "TestWatch" || test == "race detector" {
				continue
			}
			if strings.HasPrefix(test, "TestWatch/") {
				tests = appendUniqueString(tests, test)
			}
		}
		if len(tests) == 0 && race.Test != "" {
			tests = []string{race.Test}
		}
		locations := []IncidentLocation{}
		if len(race.ReadStack) > 0 {
			f := race.ReadStack[0]
			locations = append(locations, IncidentLocation{Access: "read", File: f.File, Line: f.Line, Function: f.Function, Provenance: "direct_stack_frame"})
		}
		if len(race.WriteStack) > 0 {
			f := race.WriteStack[0]
			locations = append(locations, IncidentLocation{Access: "write", File: f.File, Line: f.Line, Function: f.Function, Provenance: "direct_stack_frame"})
		}
		read, write := "unknown location", "unknown location"
		for _, location := range locations {
			value := fmt.Sprintf("%s:%d", location.File, location.Line)
			if location.Access == "read" {
				read = value
			}
			if location.Access == "write" {
				write = value
			}
		}
		functions := []string{}
		for _, location := range locations {
			if location.Function != "" {
				functions = append(functions, location.Function)
			}
		}
		proposed := "The observed stacks are consistent with concurrent lifecycle activity between the test setup/cleanup path and cacher watch creation, but stack proximity alone does not establish which synchronization or ownership rule is violated."
		if len(functions) == 0 {
			proposed = "The race report identifies conflicting accesses, but does not contain enough function information to propose a more specific mechanism."
		}
		prRelationship := "No demonstrated PR relationship; base-versus-head verification is unavailable."
		causality := 0.0
		for _, delta := range report.Deltas {
			for _, location := range locations {
				if delta.FilePath == location.File {
					prRelationship = "The PR modifies an observed race location; this is overlap, not proof that the PR caused the race."
					causality = 0.2
				}
			}
		}
		executionContext := ""
		if race.Test != "" {
			executionContext = " during " + race.Test
		}
		incidents = append(incidents, FailureIncident{ID: fmt.Sprintf("incident:race:%d", index+1), Category: "go_data_race", AffectedTests: tests, ObservedLocations: locations, ObservedExplanation: fmt.Sprintf("The Go race detector directly observed a read at %s and a write at %s%s. This establishes conflicting concurrent accesses, not their root cause.", read, write, executionContext), ProposedExplanation: proposed, PRRelationship: prRelationship, ObservedConfidence: 1, ExplanationConfidence: 0.35, CausalityConfidence: causality, Uncertainty: []string{"The report does not by itself prove which goroutine should own or synchronize the raced state.", "PR causality requires base-versus-head or equivalent verification."}, EvidenceIDs: race.EvidenceIDs})
	}
	if len(incidents) == 0 && len(report.FailureEpisodes) > 0 {
		tests := []string{}
		for _, episode := range report.FailureEpisodes {
			tests = appendUniqueString(tests, episode.TestIdentifier)
		}
		incidents = append(incidents, FailureIncident{ID: "incident:observed-failures", Category: string(report.Classification), AffectedTests: tests, ObservedExplanation: "CI evidence records failed tests, but no structured race or compiler diagnostic was available to establish a more specific incident.", ProposedExplanation: "No evidence-backed mechanism established.", PRRelationship: "No demonstrated PR relationship; base-versus-head verification is unavailable.", ObservedConfidence: 1, ExplanationConfidence: 0, CausalityConfidence: 0, Uncertainty: []string{"Only the recorded failure observation is established."}})
	}
	return incidents
}

func appendUniqueString(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

// Race reports retain standard-library frames because they are part of the
// goroutine creation evidence. They are not promoted to repository candidates
// by architectureFrames, which intentionally filters runtime/toolchain paths.
func normalizeRacePath(path string) string {
	path = filepath.ToSlash(strings.TrimSpace(path))
	if marker := "/kubernetes/"; strings.Contains(path, marker) {
		path = path[strings.Index(path, marker)+len(marker):]
	}
	return strings.TrimPrefix(path, "./")
}

func isCIEvidenceKind(kind string) bool {
	return kind == "ci_log" || kind == "original_ci_log" || kind == "junit_report" || kind == "junit_xml" || kind == "test_report" || kind == "ci_artifact" || kind == "tap_report" || kind == "runtime_exception_report" || kind == "build_diagnostic"
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
	for _, match := range tapFailure.FindAllStringSubmatch(text, -1) {
		add(match[1], "TAP test failed: "+match[1])
	}
	if runtimeException.MatchString(text) {
		add("runtime exception", "runtime exception or panic was reported")
	}
	if buildDiagnostic.MatchString(text) {
		add("compiler diagnostic", "compiler or build error was reported")
	}
	if testReportFailure.MatchString(text) && !strings.Contains(text, "<testsuite") && !strings.Contains(text, "<testsuites") {
		add("test report", "test runner reported a failure or error")
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
		if err := saveEvidenceItem(d.cfg.Store, report, item); err != nil {
			return err
		}
	}
	return nil
}

func saveEvidenceItem(store *persistence.Store, report *Report, item EvidenceItem) error {
	provenance := item.Provenance
	if provenance == "" {
		provenance = "diagnosis report evidence"
	}
	return store.SaveEvidence(domain.Evidence{ID: domain.ID(item.ID), InvestigationID: domain.ID(report.InvestigationID), Type: domain.EvidenceType(item.Kind), Source: item.Source, Timestamp: report.CreatedAt, ContentRef: item.Kind, Digest: item.Digest, Payload: item.Detail, Provenance: provenance, ClaimKind: item.ClaimKind, Basis: item.Basis, DeclarationID: item.DeclarationID, AccessID: item.AccessID, InstanceID: item.InstanceID, RunID: item.RunID, Ordering: item.Ordering, Revision: item.Revision, ExecutionID: item.ExecutionID, WorkflowRunID: item.WorkflowRunID, BuildID: item.BuildID, SourceRevision: item.SourceRevision, TestAttemptID: item.TestAttemptID, ArtifactRef: item.ArtifactID, ParserVersion: item.ParserVersion, TraceFormat: item.TraceFormat, ReportID: item.ReportID, ArtifactDigest: item.ArtifactDigest, StorageRef: item.StorageRef, ParserName: item.ParserName, ArtifactCategory: item.ArtifactCategory, ArtifactFormat: item.ArtifactFormat, DecoderStatus: item.DecoderStatus})
}

func evidenceItemFromDomain(evidence domain.Evidence) EvidenceItem {
	return EvidenceItem{
		ID:               string(evidence.ID),
		Kind:             string(evidence.Type),
		ClaimKind:        evidence.ClaimKind,
		Basis:            evidence.Basis,
		DeclarationID:    evidence.DeclarationID,
		AccessID:         evidence.AccessID,
		InstanceID:       evidence.InstanceID,
		RunID:            evidence.RunID,
		Ordering:         evidence.Ordering,
		Source:           evidence.Source,
		Digest:           evidence.Digest,
		Detail:           evidence.Payload,
		Provenance:       evidence.Provenance,
		Revision:         evidence.Revision,
		ExecutionID:      evidence.ExecutionID,
		WorkflowRunID:    evidence.WorkflowRunID,
		BuildID:          evidence.BuildID,
		SourceRevision:   evidence.SourceRevision,
		TestAttemptID:    evidence.TestAttemptID,
		ArtifactID:       string(evidence.ArtifactID),
		ParserVersion:    evidence.ParserVersion,
		TraceFormat:      evidence.TraceFormat,
		ReportID:         evidence.ReportID,
		ArtifactDigest:   evidence.ArtifactDigest,
		StorageRef:       evidence.StorageRef,
		ParserName:       evidence.ParserName,
		ArtifactCategory: evidence.ArtifactCategory,
		ArtifactFormat:   evidence.ArtifactFormat,
		DecoderStatus:    evidence.DecoderStatus,
	}
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
	addFrames := func(text string, evidenceID domain.ID) {
		for _, m := range pythonFrame.FindAllStringSubmatch(text, -1) {
			addFrame(&out, seen, normalizeEvidencePath(m[1]), atoi(m[2]), failureIDs, evidenceID)
		}
		for _, m := range goFrame.FindAllStringSubmatch(text, -1) {
			addFrame(&out, seen, normalizeEvidencePath(m[1]), atoi(m[2]), failureIDs, evidenceID)
		}
	}
	for _, a := range b.Results {
		text := a.Stderr
		failureIDs := failureIDsForText(a.Stderr, failures)
		for _, m := range pythonFrame.FindAllStringSubmatch(text, -1) {
			addFrame(&out, seen, normalizeEvidencePath(m[1]), atoi(m[2]), failureIDs, "")
		}
		for _, m := range goFrame.FindAllStringSubmatch(text, -1) {
			addFrame(&out, seen, normalizeEvidencePath(m[1]), atoi(m[2]), failureIDs, "")
		}
	}
	for _, item := range evidence {
		if isCIEvidenceKind(item.Kind) {
			traces := parseRaceReports(item.Detail)
			if len(traces) > 0 {
				for _, race := range traces {
					for _, frame := range append(append([]localization.Frame{}, race.ReadStack...), race.WriteStack...) {
						addFrame(&out, seen, frame.File, frame.Line, failureIDs, domain.ID(item.ID))
					}
				}
				continue
			}
			addFrames(item.Detail, domain.ID(item.ID))
		}
	}
	return out
}

func addFrame(out *[]localization.Frame, seen map[string]bool, file string, line int, failureIDs []string, evidenceID domain.ID) {
	if file == "" || line <= 0 {
		return
	}
	key := fmt.Sprintf("%s:%d", file, line)
	if seen[key] {
		return
	}
	seen[key] = true
	frame := localization.Frame{File: file, Line: line, FailureIDs: failureIDs}
	if evidenceID != "" {
		frame.EvidenceIDs = []domain.ID{evidenceID}
	}
	*out = append(*out, frame)
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
	seen := map[string]bool{}
	var files []string
	add := func(path string) {
		path = filepath.ToSlash(filepath.Clean(strings.TrimPrefix(path, "./")))
		if path == "." || path == "" || seen[path] {
			return
		}
		seen[path] = true
		files = append(files, path)
	}
	// Race access locations are the highest-value indexing seeds. Creation
	// stacks are retained as context but are added after the conflicting sides.
	for _, item := range evidence {
		if !isCIEvidenceKind(item.Kind) {
			continue
		}
		for _, race := range parseRaceReports(item.Detail) {
			if len(race.ReadStack) > 0 {
				add(race.ReadStack[0].File)
			}
			if len(race.WriteStack) > 0 {
				add(race.WriteStack[0].File)
			}
			for _, stack := range race.GoroutineCreationStacks {
				for _, frame := range stack {
					if !strings.HasPrefix(frame.File, "/usr/") {
						add(frame.File)
					}
				}
			}
		}
	}
	frames := architectureFrames(b, nil, evidence)
	for _, frame := range frames {
		add(frame.File)
		if len(files) >= 12 {
			break
		}
	}
	if len(files) > 12 {
		files = files[:12]
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

func refineEvidenceLikelyFiles(report *Report) {
	if report.NormalizedEvidence == nil && report.Baseline.Source != "ci_artifact" {
		return
	}
	reasons := map[string][]string{}
	files := []string{}
	add := func(path, reason string) {
		if path == "" {
			return
		}
		if _, exists := reasons[path]; !exists {
			files = append(files, path)
		}
		reasons[path] = appendUniqueString(reasons[path], reason)
	}
	for _, race := range report.RaceReports {
		if len(race.ReadStack) > 0 {
			add(race.ReadStack[0].File, "direct race read location")
		}
		if len(race.WriteStack) > 0 {
			add(race.WriteStack[0].File, "direct race write location")
		}
		for _, stack := range race.GoroutineCreationStacks {
			for _, frame := range stack {
				if !strings.HasPrefix(frame.File, "/usr/") {
					add(frame.File, "race goroutine creation stack")
				}
			}
		}
	}
	for _, candidate := range report.Candidates {
		if len(files) >= 8 {
			break
		}
		reason := candidate.Location.Provenance
		if reason == "" {
			reason = candidate.Location.LocationType
		}
		if reason == "enclosing_symbol" || reason == "direct_stack_frame" || reason == "observed_frame" || reason == "inferred_caller" {
			add(candidate.Location.FilePath, reason)
		}
	}
	if len(files) > 8 {
		files = files[:8]
	}
	report.Localization.LikelyFiles = files
	report.Localization.LikelyFileReasons = reasons
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

func observedFrameEvidence(frames []localization.Frame) []EvidenceItem {
	out := make([]EvidenceItem, 0, len(frames))
	for _, frame := range frames {
		detail := fmt.Sprintf("CI execution stack frame observed at %s:%d; this establishes a reported location, not causality", frame.File, frame.Line)
		out = append(out, EvidenceItem{
			ID:   "E-frame-" + digestString(frame.File + ":" + fmt.Sprint(frame.Line))[:12],
			Kind: "execution_stack_frame", Source: frame.File, Digest: digestString(detail), Detail: detail,
			Provenance: "parsed from original CI failure evidence",
		})
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
