package diagnosis

import (
	"context"
	"os"
	"path/filepath"
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
