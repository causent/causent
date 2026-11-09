package diagnosis

import (
	"context"
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
