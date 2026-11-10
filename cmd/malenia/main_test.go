package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/causent/malenia/internal/diagnosis"
)

func TestDiagnosisTextUsesOneIncidentFindingAndPreservesEvidence(t *testing.T) {
	data, err := os.ReadFile("../../internal/diagnosis/testdata/kubernetes-run44-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var report diagnosis.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	text := diagnosisText(report)
	if strings.Count(text, "incident diagnosis:") != 1 || strings.Count(text, "go_data_race") != 1 {
		t.Fatalf("incident was not rendered exactly once:\n%s", text)
	}
	if !strings.Contains(text, "ci-evidence-d64c88c2758e") {
		t.Fatalf("incident evidence was not preserved:\n%s", text)
	}
	if !strings.Contains(text, "evidence: ci-evidence-d64c88c2758e") {
		t.Fatalf("incident evidence was not rendered:\n%s", text)
	}
	if strings.Contains(text, "Candidate location X may explain") {
		t.Fatalf("generic candidate hypothesis was rendered:\n%s", text)
	}
}
