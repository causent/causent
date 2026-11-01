package agent

import "testing"

func TestValidateReportRejectsUnsupportedClaims(t *testing.T) {
	err := ValidateReport(Report{Hypotheses: []Hypothesis{{Statement: "x", Confidence: .5, EvidenceIDs: []string{"missing"}}}}, []Evidence{{ID: "E1"}})
	if err == nil {
		t.Fatal("expected unknown evidence rejection")
	}
}

func TestValidateReportRejectsInvalidConfidence(t *testing.T) {
	if err := ValidateReport(Report{Hypotheses: []Hypothesis{{Statement: "x", Confidence: 2}}}, nil); err == nil {
		t.Fatal("expected confidence rejection")
	}
}
