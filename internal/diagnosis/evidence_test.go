package diagnosis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseJUnitXMLFailureIsNormalized(t *testing.T) {
	got, err := ParseJUnitXML(`<testsuites><testsuite><testcase classname="pkg.Test" name="broken"><failure message="want 1 got 2">trace</failure></testcase></testsuite></testsuites>`, EvidenceProvenance{Provider: "ci"})
	if err != nil || len(got.Executions) != 1 || got.Executions[0].State != StateFailed {
		t.Fatalf("evidence=%#v err=%v", got, err)
	}

	if got.Executions[0].Tests[0].Message != "want 1 got 2" {
		t.Fatalf("tests=%#v", got.Executions[0].Tests)
	}
}

func TestParseJUnitXMLSingleSuiteRoot(t *testing.T) {
	got, err := ParseJUnitXML(`<testsuite name="unit"><testcase name="ok"/></testsuite>`, EvidenceProvenance{})
	if err != nil || len(got.Executions) != 1 || len(got.Executions[0].Tests) != 1 || got.Executions[0].Tests[0].State != StatePassed {
		t.Fatalf("evidence=%#v err=%v", got, err)
	}
}

func TestParseJUnitXMLMalformedIsNotPass(t *testing.T) {
	got, err := ParseJUnitXML(`<testsuites><testsuite><testcase>`, EvidenceProvenance{})
	if err == nil || got.Executions[0].State == StatePassed {
		t.Fatalf("evidence=%#v err=%v", got, err)
	}
}

func TestParseCITextCompilerLocation(t *testing.T) {
	got := ParseCITextEvidence("compile: src/main.go:42:7: undefined: missing\nerror: build failed", EvidenceProvenance{Provider: "ci"})
	test := got.Executions[0].Tests[0]
	if got.Executions[0].State != StateFailed || test.File != "src/main.go" || test.Line != 42 {
		t.Fatalf("evidence=%#v", got)
	}
}

func TestParseCITextEvidencePreservesLargeLogSuffixAndRaceFailure(t *testing.T) {
	content := strings.Repeat("setup output\n", 12000) +
		"WARNING: DATA RACE\n" +
		"k8s.io/apiserver/pkg/storage/cacher/cache.go:123 +0x1a\n" +
		"FAIL\tk8s.io/apiserver/pkg/storage/cacher\t0.42s\n"
	got := ParseCITextEvidence(content, EvidenceProvenance{Provider: "prow"})
	if len(got.Executions) != 1 || got.Executions[0].State != StateFailed {
		t.Fatalf("expected failed execution, got %#v", got.Executions)
	}
	if !strings.Contains(got.RawEvidence[0].Content, "WARNING: DATA RACE") {
		t.Fatal("large-log normalization discarded the terminal race report")
	}
	if len(got.Executions[0].Tests) == 0 {
		t.Fatal("expected race/package failure observations")
	}
}

func TestNormalizedStatesDoNotBecomePass(t *testing.T) {
	for _, state := range []ObservationState{StateCancelled, StateTimedOut, StateNotExecuted, StateSkipped, StateUnknown} {
		b := normalizedBaseline(NormalizedEvidence{Executions: []CIExecution{{State: state}}}, nil)
		if Classify(b.Results) == ClassNotReproduced {
			t.Fatalf("state %s was treated as pass", state)
		}
	}
}

func TestDecideReproductionDefersWhenEvidenceIsComplete(t *testing.T) {
	decision := DecideReproduction(NormalizedEvidence{Executions: []CIExecution{{State: StateFailed}}}, []string{"go", "test", "./pkg/failing"})
	if decision.Required || decision.Reason == "" {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestDecideReproductionRequiresIncompleteEvidence(t *testing.T) {
	decision := DecideReproduction(NormalizedEvidence{Executions: []CIExecution{{State: StateTimedOut}}}, []string{"go", "test", "./pkg/failing"})
	if !decision.Required || decision.Reason != ReasonIncompleteEvidence || decision.Command[0] != "go" || decision.ExpectedQuestion == "" {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestDecideReproductionIdentifiesConflictingEvidence(t *testing.T) {
	decision := DecideReproduction(NormalizedEvidence{Executions: []CIExecution{
		{State: StateFailed},
		{State: StatePassed},
	}}, []string{"go", "test", "./pkg/failing"})
	if !decision.Required || decision.Reason != ReasonFlakyTestVerification {
		t.Fatalf("decision=%#v", decision)
	}
}

func TestDiagnoseEvidenceDoesNotCallExecutorOrClaimRegression(t *testing.T) {
	got, err := DiagnoseEvidence(context.Background(), Config{
		RepoPath: "/does/not/need/to/exist",
		Evidence: nil,
	}, NormalizedEvidence{Executions: []CIExecution{{
		State:       StateFailed,
		RawEvidence: []RawCIEvidence{{ID: "raw-1", Kind: "ci_log", Content: "FAIL TestBroken"}},
	}}})
	if err != nil || got.Classification != ClassTestFailureObserved || got.ReproductionStatus != "deferred" {
		t.Fatalf("report=%#v err=%v", got, err)
	}
	if got.ReproductionDeferredReason == "" {
		t.Fatal("expected explicit deferred reason")
	}
	if got.NormalizedEvidence == nil || len(got.NormalizedEvidence.Executions) != 1 {
		t.Fatalf("normalized evidence missing from report: %#v", got.NormalizedEvidence)
	}
	if got.ReproductionDecision.Required {
		t.Fatalf("complete failure evidence should defer reproduction: %#v", got.ReproductionDecision)
	}
}

func TestRealCIEvidenceAcceptanceScenarios(t *testing.T) {
	tests := []struct {
		name             string
		evidence         NormalizedEvidence
		wantClass        Classification
		wantReproduction bool
		wantReason       ReproductionReason
	}{
		{
			name:       "deterministic junit assertion",
			evidence:   mustJUnitEvidence(t, `<testsuites><testsuite name="unit"><testcase classname="pkg.Test" name="broken"><failure message="want 1 got 2">trace</failure></testcase></testsuite></testsuites>`),
			wantClass:  ClassTestFailureObserved,
			wantReason: ReasonEvidenceSufficient,
		},
		{
			name:       "compiler failure",
			evidence:   ParseCITextEvidence("src/main.go:42:7: undefined: missing\nerror: build failed", EvidenceProvenance{Provider: "github-actions"}),
			wantClass:  ClassTestFailureObserved,
			wantReason: ReasonEvidenceSufficient,
		},
		{
			name:       "infrastructure failure",
			evidence:   ParseCITextEvidence("error: connection refused while contacting the test service", EvidenceProvenance{Provider: "github-actions"}),
			wantClass:  ClassInfrastructure,
			wantReason: ReasonEvidenceSufficient,
		},
		{
			name: "flaky test requires verification",
			evidence: NormalizedEvidence{Executions: []CIExecution{
				{ID: "run-1", State: StateFailed},
				{ID: "run-2", State: StatePassed},
			}},
			wantClass:        ClassFlaky,
			wantReproduction: true,
			wantReason:       ReasonFlakyTestVerification,
		},
		{
			name:             "missing report is inconclusive",
			evidence:         NormalizedEvidence{},
			wantClass:        ClassInconclusive,
			wantReproduction: true,
			wantReason:       ReasonNoExecutionEvidence,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := DiagnoseEvidence(context.Background(), Config{
				RepoPath: "/not-checked-out",
				Command:  []string{"go", "test", "./..."},
			}, tt.evidence)
			if err != nil {
				t.Fatalf("diagnose evidence: %v", err)
			}
			if report.Classification != tt.wantClass {
				t.Fatalf("classification=%s, want %s", report.Classification, tt.wantClass)
			}
			if report.ReproductionDecision.Required != tt.wantReproduction {
				t.Fatalf("reproduction required=%t, want %t (%#v)", report.ReproductionDecision.Required, tt.wantReproduction, report.ReproductionDecision)
			}
			if report.ReproductionDecision.Reason != tt.wantReason {
				t.Fatalf("reproduction reason=%s, want %s", report.ReproductionDecision.Reason, tt.wantReason)
			}
			if report.Environment.Isolation != "external CI evidence" {
				t.Fatalf("evidence-first path used unexpected environment: %#v", report.Environment)
			}
			if !tt.wantReproduction && len(report.Evidence) == 0 {
				t.Fatal("expected an evidence-backed useful diagnosis")
			}
		})
	}
}

func mustJUnitEvidence(t *testing.T, content string) NormalizedEvidence {
	t.Helper()
	evidence, err := ParseJUnitXML(content, EvidenceProvenance{Provider: "github-actions"})
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return evidence
}

func TestKubernetesM5FixtureIsOfflineDiagnosable(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "m5", "kubernetes")
	logData, err := os.ReadFile(filepath.Join(root, "ci.log"))
	if err != nil {
		t.Fatal(err)
	}
	junitData, err := os.ReadFile(filepath.Join(root, "junit.xml"))
	if err != nil {
		t.Fatal(err)
	}
	logEvidence := ParseCITextEvidence(string(logData), EvidenceProvenance{Provider: "fixture"})
	junitEvidence, err := ParseJUnitXML(string(junitData), EvidenceProvenance{Provider: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	logEvidence.Executions = append(logEvidence.Executions, junitEvidence.Executions...)
	logEvidence.RawEvidence = append(logEvidence.RawEvidence, junitEvidence.RawEvidence...)
	report, err := DiagnoseEvidence(context.Background(), Config{
		RepoPath: "offline-fixture",
		Command:  []string{"go", "test", "./..."},
	}, logEvidence)
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != ClassInfrastructure || !report.ReproductionDecision.Required {
		t.Fatalf("fixture report=%#v", report)
	}
	if report.Environment.Isolation != "external CI evidence" {
		t.Fatalf("fixture unexpectedly used repository execution: %#v", report.Environment)
	}
}

func TestProwLintFailureClassificationAndTraceability(t *testing.T) {
	// Regression test for kubernetes/kubernetes#143709 Prow lint failure diagnosis.
	// Requirements:
	// 1. Classify as lint_failure_observed, not test_failure_observed
	// 2. Preserve Prow job identity and log location
	// 3. Extract only actual lint ERROR lines, not all warnings
	// 4. Do not claim causality without base/head evidence
	root := filepath.Join("..", "..", "testdata", "prow-lint-failure")
	logData, err := os.ReadFile(filepath.Join(root, "ci.log"))
	if err != nil {
		t.Fatal(err)
	}
	// Note: In workflow mode (try-public-pr.yml), SourceURL and LogURL would be populated
	// from GitHub/Prow APIs. In CLI/offline mode, only URI (local path) is available.
	provenance := EvidenceProvenance{
		Provider: "offline",
		URI:      filepath.Join(root, "ci.log"),
	}
	evidence := ParseCITextEvidence(string(logData), provenance)

	// Verify Prow job identity was extracted from log content
	if len(evidence.Executions) == 0 {
		t.Fatal("no executions extracted")
	}
	exec := evidence.Executions[0]
	if exec.Identity.Job != "verify.golangci-lint-pr-hints" {
		t.Errorf("job identity not extracted: got %q, want verify.golangci-lint-pr-hints", exec.Identity.Job)
	}
	if exec.Identity.Step != "verify-golangci-lint-pr-hints.sh" {
		t.Errorf("step identity not extracted: got %q", exec.Identity.Step)
	}

	// Verify provenance is preserved in raw evidence
	if len(evidence.RawEvidence) == 0 || evidence.RawEvidence[0].Provenance.URI != provenance.URI {
		t.Errorf("URI not preserved in raw evidence")
	}

	// Verify lint failures were extracted (should be 2 ERROR lines)
	if len(exec.Tests) != 2 {
		t.Errorf("expected 2 lint failures, got %d: %+v", len(exec.Tests), exec.Tests)
	}

	// Verify the extracted failures are the actual ERROR lines
	for i, test := range exec.Tests {
		if !strings.HasPrefix(test.Name, "lint:") {
			t.Errorf("test[%d] name should start with 'lint:', got %q", i, test.Name)
		}
		if test.File == "" || test.Line == 0 {
			t.Errorf("test[%d] missing file:line: %+v", i, test)
		}
		if test.EvidenceID == "" {
			t.Errorf("test[%d] missing evidence ID", i)
		}
	}

	// Verify the specific failures match the actual log content
	expectedFailures := map[string]bool{
		"pkg/kubelet/kuberuntime/kuberuntime_manager.go:2227":      true,
		"pkg/kubelet/kuberuntime/kuberuntime_manager_test.go:7620": true,
	}
	found := 0
	for _, test := range exec.Tests {
		key := fmt.Sprintf("%s:%d", test.File, test.Line)
		if expectedFailures[key] {
			found++
		}
	}
	if found != 2 {
		t.Errorf("did not find expected lint failures, got: %+v", exec.Tests)
	}

	// Now test the full diagnosis
	report, err := DiagnoseEvidence(context.Background(), Config{
		RepoPath: "offline-prow-evidence",
		Command:  []string{"go", "test", "./..."},
	}, evidence)
	if err != nil {
		t.Fatal(err)
	}

	// Requirement 1: Must classify as lint_failure_observed
	if report.Classification != ClassLintFailureObserved {
		t.Errorf("classification: got %q, want %q", report.Classification, ClassLintFailureObserved)
	}

	// Requirement 2: Provenance must be in the report
	// The provenance is stored in the normalized evidence
	if report.NormalizedEvidence == nil || len(report.NormalizedEvidence.RawEvidence) == 0 {
		t.Errorf("normalized evidence missing")
	} else {
		gotProv := report.NormalizedEvidence.RawEvidence[0].Provenance
		if gotProv.Provider != provenance.Provider {
			t.Errorf("provider not preserved: got %q, want %q", gotProv.Provider, provenance.Provider)
		}
		if gotProv.URI != provenance.URI {
			t.Errorf("URI not preserved: got %q, want %q", gotProv.URI, provenance.URI)
		}
	}

	// Requirement 4: Must not claim causality (statement should mention uncertainty)
	if len(report.Claims) == 0 {
		t.Fatal("no claims generated")
	}
	classificationClaim := report.Claims[0]
	if !strings.Contains(classificationClaim.Statement, "does not establish") {
		t.Errorf("claim should not assert causality without base/head evidence: %q", classificationClaim.Statement)
	}

	// The normalized evidence should preserve the test observations with proper identity
	if report.NormalizedEvidence == nil || len(report.NormalizedEvidence.Executions) == 0 {
		t.Fatal("normalized evidence missing")
	}
	normExec := report.NormalizedEvidence.Executions[0]
	if normExec.Identity.Job == "" {
		t.Error("Prow job identity not preserved in normalized evidence")
	}

	// Test the three consistency requirements:

	// 1. Provenance: Offline mode uses local URI, not remote URLs
	if normExec.RawEvidence[0].Provenance.Provider != "offline" {
		t.Errorf("expected offline provider for CLI fixture, got %q", normExec.RawEvidence[0].Provenance.Provider)
	}
	if normExec.RawEvidence[0].Provenance.URI == "" {
		t.Error("URI must be populated in offline mode")
	}
	if normExec.RawEvidence[0].Provenance.SourceURL != "" {
		t.Error("SourceURL should be empty in offline mode (only populated by workflow integration)")
	}

	// 2. Identity inheritance: Each TestObservation must have identity populated
	for i, test := range normExec.Tests {
		if test.Identity.Job == "" {
			t.Errorf("test[%d] identity.Job is empty; identity must be populated from parent execution", i)
		}
		if test.Identity.Job != normExec.Identity.Job {
			t.Errorf("test[%d] identity mismatch: got %q, want %q", i, test.Identity.Job, normExec.Identity.Job)
		}
	}

	// 3. Uncertainty filtering: Bisect/localization uncertainties should not appear
	for _, unc := range report.Uncertainty {
		if strings.Contains(unc, "bisect") || strings.Contains(unc, "first-bad") || strings.Contains(unc, "known-good commit") {
			t.Errorf("irrelevant localization uncertainty in evidence-only mode: %q", unc)
		}
	}

	// Verify lint-hints distinction is present
	foundLintHintsGuidance := false
	for _, unc := range report.Uncertainty {
		if strings.Contains(unc, "lint-hints") || strings.Contains(unc, "acceptable to merge") {
			foundLintHintsGuidance = true
			break
		}
	}
	if !foundLintHintsGuidance {
		t.Error("uncertainty should clarify that lint-hints findings may be acceptable per project guidelines")
	}
}
