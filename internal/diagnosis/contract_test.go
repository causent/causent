package diagnosis

import "testing"

func TestValidateContractRejectsUnknownEvidence(t *testing.T) {
	err := ValidateContract(Report{Evidence: []EvidenceItem{{ID: "E1"}}, Claims: []Claim{{ID: "H1", Statement: "x", Confidence: .5, Supporting: []string{"E2"}}}})
	if err == nil {
		t.Fatal("expected contract failure")
	}
}
