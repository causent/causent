package diagnosis

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ObservationState is the provider-neutral state of a test or execution.
type ObservationState string

const (
	StatePassed      ObservationState = "passed"
	StateFailed      ObservationState = "failed"
	StateSkipped     ObservationState = "skipped"
	StateCancelled   ObservationState = "cancelled"
	StateTimedOut    ObservationState = "timed_out"
	StateNotExecuted ObservationState = "not_executed"
	StateUnknown     ObservationState = "unknown"
)

type CIIdentity struct {
	Workflow string `json:"workflow,omitempty"`
	Job      string `json:"job,omitempty"`
	Step     string `json:"step,omitempty"`
}

type EvidenceProvenance struct {
	Provider    string    `json:"provider,omitempty"`
	URI         string    `json:"uri,omitempty"`
	SourceURL   string    `json:"source_url,omitempty"` // Original CI job URL (Prow view, GitHub Actions run)
	LogURL      string    `json:"log_url,omitempty"`    // Direct log URL (GCS bucket, etc.)
	Artifact    string    `json:"artifact,omitempty"`
	CollectedAt time.Time `json:"collected_at,omitempty"`
}

type RawCIEvidence struct {
	ID          string             `json:"id"`
	Kind        string             `json:"kind"`
	Content     string             `json:"content"`
	Provenance  EvidenceProvenance `json:"provenance"`
	Limitations []string           `json:"limitations,omitempty"`
}

type TestObservation struct {
	Identity   CIIdentity       `json:"identity"`
	Name       string           `json:"name"`
	State      ObservationState `json:"state"`
	Message    string           `json:"message,omitempty"`
	File       string           `json:"file,omitempty"`     // Source code file path
	Line       int              `json:"line,omitempty"`     // Source code line number
	LogLine    int              `json:"log_line,omitempty"` // Line number within CI log where diagnostic appears
	ExitCode   *int             `json:"exit_code,omitempty"`
	Status     string           `json:"status,omitempty"`
	EvidenceID string           `json:"evidence_id,omitempty"` // Links to raw CI log in RawCIEvidence
}

type CIExecution struct {
	ID          string            `json:"id"`
	Identity    CIIdentity        `json:"identity"`
	State       ObservationState  `json:"state"`
	ExitCode    *int              `json:"exit_code,omitempty"`
	Status      string            `json:"status,omitempty"`
	Tests       []TestObservation `json:"tests,omitempty"`
	RawEvidence []RawCIEvidence   `json:"raw_evidence,omitempty"`
	Limitations []string          `json:"limitations,omitempty"`
	StartedAt   time.Time         `json:"started_at,omitempty"`
	FinishedAt  time.Time         `json:"finished_at,omitempty"`
}

// NormalizedEvidence is the provider-neutral input to evidence-first diagnosis.
type NormalizedEvidence struct {
	Executions  []CIExecution   `json:"executions"`
	RawEvidence []RawCIEvidence `json:"raw_evidence,omitempty"`
	Limitations []string        `json:"limitations,omitempty"`
}

type ReproductionReason string

const (
	ReasonIncompleteEvidence    ReproductionReason = "incomplete_evidence"
	ReasonConflictingEvidence   ReproductionReason = "conflicting_evidence"
	ReasonFlakyTestVerification ReproductionReason = "flaky_test_verification"
	ReasonRuntimeHypothesis     ReproductionReason = "runtime_hypothesis_verification"
	ReasonNoExecutionEvidence   ReproductionReason = "no_execution_evidence"
	ReasonEvidenceSufficient    ReproductionReason = "evidence_sufficient"
)

// ReproductionDecision records whether another execution could materially
// improve an evidence-first diagnosis. It does not execute anything.
type ReproductionDecision struct {
	Required         bool               `json:"required"`
	Reason           ReproductionReason `json:"reason"`
	Explanation      string             `json:"explanation"`
	Command          []string           `json:"command,omitempty"`
	ExpectedQuestion string             `json:"expected_question,omitempty"`
}

func DecideReproduction(input NormalizedEvidence, command []string) ReproductionDecision {
	if len(input.Executions) == 0 {
		return ReproductionDecision{
			Required: true, Reason: ReasonNoExecutionEvidence,
			Explanation: "no execution evidence was supplied",
			Command:     command, ExpectedQuestion: "What happens when the relevant command is executed on the target revision?",
		}
	}
	var failed, passed bool
	for _, execution := range input.Executions {
		failed = failed || execution.State == StateFailed
		passed = passed || execution.State == StatePassed
		switch execution.State {
		case StateUnknown, StateCancelled, StateTimedOut, StateNotExecuted:
			return ReproductionDecision{
				Required: true, Reason: ReasonIncompleteEvidence,
				Explanation: "execution evidence is incomplete",
				Command:     command, ExpectedQuestion: "Did the relevant command actually execute and what result did it produce?",
			}
		}
	}
	if failed && passed {
		return ReproductionDecision{
			Required: true, Reason: ReasonFlakyTestVerification,
			Explanation: "evidence contains both passing and failing executions",
			Command:     command, ExpectedQuestion: "Is the observed failure reproducible or intermittent on the target revision?",
		}
	}
	return ReproductionDecision{
		Required: false, Reason: ReasonEvidenceSufficient,
		Explanation: "execution evidence is complete enough for an initial diagnosis",
		Command:     command,
	}
}

type junitFile struct {
	Suites []junitSuite `xml:"testsuite"`
	Cases  []junitCase  `xml:"testcase"`
}
type parserOptions struct{ maxBytes int }

var ciLocation = regexp.MustCompile(`(?:^|\s)([A-Za-z0-9_./-]+\.(?:go|rs|java|py|js|ts|c|cc|cpp|h)):(\d+)(?::(\d+))?`)
var lintErrorLine = regexp.MustCompile(`^ERROR:\s+([A-Za-z0-9_./-]+\.(?:go|rs|java|py|js|ts|c|cc|cpp|h)):(\d+)(?::(\d+))?:\s+([^:]+):\s+(.+)$`)
var prowJobPattern = regexp.MustCompile(`^\+\+\+\s+Running\s+case:\s+([^\s]+)`)
var prowWorkdirPattern = regexp.MustCompile(`^\+\+\+\s+working\s+dir:\s+(.+)$`)

func extractProwIdentity(content string) CIIdentity {
	var identity CIIdentity
	for _, line := range strings.Split(content, "\n") {
		if m := prowJobPattern.FindStringSubmatch(line); m != nil {
			identity.Job = m[1]
		}
		if strings.HasPrefix(line, "Verifying ") {
			identity.Step = strings.TrimPrefix(line, "Verifying ")
		}
		if m := prowWorkdirPattern.FindStringSubmatch(line); m != nil && identity.Workflow == "" {
			// Extract repo name from workdir like /home/prow/go/src/k8s.io/kubernetes
			parts := strings.Split(m[1], "/")
			if len(parts) > 0 {
				identity.Workflow = parts[len(parts)-1]
			}
		}
	}
	return identity
}

func extractLintFailures(content, evidenceID string, state ObservationState, identity CIIdentity) []TestObservation {
	var failures []TestObservation
	seen := map[string]bool{}
	lines := strings.Split(content, "\n")
	for logLineNum, line := range lines {
		if m := lintErrorLine.FindStringSubmatch(line); m != nil {
			file := m[1]
			lineNum, _ := strconv.Atoi(m[2])
			linter := m[4]
			message := m[5]
			key := fmt.Sprintf("%s:%d", file, lineNum)
			if !seen[key] {
				seen[key] = true
				failures = append(failures, TestObservation{
					Identity:   identity,
					Name:       fmt.Sprintf("lint: %s", linter),
					State:      state,
					File:       file,
					Line:       lineNum,
					LogLine:    logLineNum + 1, // 1-indexed for human readability
					Message:    message,
					EvidenceID: evidenceID,
				})
			}
		}
	}
	return failures
}

func boundedCIEvidence(kind, content string, limit int) (RawCIEvidence, []string) {
	if limit <= 0 {
		limit = 64 << 10
	}
	raw := RawCIEvidence{ID: "ci-evidence-" + digestString(content)[:12], Kind: kind, Content: content}
	if len(content) > limit {
		// CI systems commonly print setup first and the actual failing package,
		// race report, or JUnit summary last. Keeping only the prefix loses the
		// useful part of large Prow logs. Preserve both ends while keeping the
		// stored evidence bounded.
		head := limit / 2
		tail := limit - head
		raw.Content = content[:head] + "\n[... CI evidence middle omitted ...]\n" + content[len(content)-tail:]
		raw.Limitations = []string{"evidence middle was truncated to a bounded size; prefix and suffix were preserved"}
	}
	return raw, raw.Limitations
}

// ParseJUnitXML deterministically normalizes a JUnit report. A malformed
// report returns an unknown execution (never a pass) together with the error.
func ParseJUnitXML(content string, provenance EvidenceProvenance) (NormalizedEvidence, error) {
	raw, limits := boundedCIEvidence("junit_xml", content, 64<<10)
	out := NormalizedEvidence{RawEvidence: []RawCIEvidence{raw}, Limitations: limits}
	var doc junitFile
	if err := xml.Unmarshal([]byte(raw.Content), &doc); err != nil {
		out.Limitations = append(out.Limitations, "JUnit XML was malformed or incomplete")
		out.Executions = []CIExecution{{ID: raw.ID, State: StateUnknown, RawEvidence: []RawCIEvidence{raw}, Limitations: out.Limitations}}
		return out, fmt.Errorf("parse JUnit XML: %w", err)
	}
	exec := CIExecution{ID: raw.ID, State: StatePassed, RawEvidence: []RawCIEvidence{raw}}
	var rootSuite junitSuite
	rootIsSuite := false
	if err := xml.Unmarshal([]byte(raw.Content), &rootSuite); err == nil &&
		rootSuite.XMLName.Local == "testsuite" {
		doc.Suites = append(doc.Suites, rootSuite)
		rootIsSuite = true
	}
	var visit func([]junitSuite)
	visit = func(suites []junitSuite) {
		for _, suite := range suites {
			for _, c := range suite.Cases {
				state := StatePassed
				msg := ""
				if c.Failure != nil || c.Error != nil {
					state = StateFailed
					p := c.Failure
					if p == nil {
						p = c.Error
					}
					msg = strings.TrimSpace(p.Message)
					if msg == "" {
						msg = strings.TrimSpace(p.Body)
					}
				} else if c.Skipped != nil {
					state = StateSkipped
				}
				name := c.Name
				if c.ClassName != "" {
					name = c.ClassName + "::" + name
				}
				exec.Tests = append(exec.Tests, TestObservation{Name: name, State: state, Message: msg, EvidenceID: raw.ID})
				if state == StateFailed {
					exec.State = StateFailed
				}
			}
			visit(suite.Suites)
		}
	}
	visit(doc.Suites)
	if len(doc.Cases) > 0 && !rootIsSuite {
		visit([]junitSuite{{Cases: doc.Cases}})
	}
	if len(exec.Tests) == 0 {
		exec.State = StateUnknown
		exec.Limitations = append(exec.Limitations, "JUnit report contained no complete testcase set")
		out.Limitations = append(out.Limitations, exec.Limitations...)
	}
	exec.RawEvidence[0].Provenance = provenance
	exec.Status = string(exec.State)
	out.RawEvidence[0].Provenance = provenance
	out.Executions = []CIExecution{exec}
	return out, nil
}

// ParseCITextEvidence extracts bounded compiler/stack-trace and CI status
// observations. It only reports pass when the log contains an explicit pass.
func ParseCITextEvidence(content string, provenance EvidenceProvenance) NormalizedEvidence {
	raw, limits := boundedCIEvidence("ci_log", content, 64<<10)
	raw.Provenance = provenance
	lower := strings.ToLower(raw.Content)
	state := StateUnknown
	switch {
	case strings.Contains(lower, "cancelled") || strings.Contains(lower, "canceled"):
		state = StateCancelled
	case strings.Contains(lower, "timed out") || strings.Contains(lower, "timeout exceeded") || strings.Contains(lower, "deadline exceeded"):
		state = StateTimedOut
	case strings.Contains(lower, "fail") || strings.Contains(lower, "error:") || strings.Contains(lower, "data race"):
		state = StateFailed
	case strings.Contains(lower, "passed") || strings.Contains(lower, "tests passed"):
		state = StatePassed
	case strings.Contains(lower, "not executed"):
		state = StateNotExecuted
	case strings.Contains(lower, "skipped"):
		state = StateSkipped
	}

	// Detect Prow job identity from log header
	identity := extractProwIdentity(raw.Content)

	exec := CIExecution{ID: raw.ID, Identity: identity, State: state, RawEvidence: []RawCIEvidence{raw}, Limitations: limits}
	exec.Status = string(state)

	// First, check for lint ERROR lines (golangci-lint, etc.)
	// These are definitive failures, not just warnings in the log.
	lintFailures := extractLintFailures(raw.Content, raw.ID, state, identity)
	if len(lintFailures) > 0 {
		exec.Tests = lintFailures
	} else {
		// Fallback: extract generic file:line locations
		for _, m := range ciLocation.FindAllStringSubmatch(raw.Content, -1) {
			line, _ := strconv.Atoi(m[2])
			exec.Tests = append(exec.Tests, TestObservation{Identity: identity, Name: "observed location", State: state, File: m[1], Line: line, EvidenceID: raw.ID})
		}
	}

	out := NormalizedEvidence{Executions: []CIExecution{exec}, RawEvidence: []RawCIEvidence{raw}, Limitations: limits}
	return out
}
