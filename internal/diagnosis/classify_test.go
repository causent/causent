package diagnosis

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRun46DoesNotGenerateUnsupportedAffectedFilesClaim(t *testing.T) {
	data, err := os.ReadFile("testdata/kubernetes-run46-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if err := ValidateContract(report); err == nil {
		t.Fatal("run #46 fixture should expose the unsupported claim regression")
	}
	claims := buildClaims(report.Classification, report.Localization, report.Evidence)
	for _, claim := range claims {
		if claim.ID == "H-affected-files" {
			t.Fatalf("unsupported affected-files claim generated: %#v", claim)
		}
	}

	claims = buildClaims(report.Classification, Localization{
		LikelyFiles: []string{"direct.go", "inferred.go"},
		LikelyFileReasons: map[string][]string{
			"direct.go":   {"direct race read location"},
			"inferred.go": {"inferred_caller"},
		},
	}, []EvidenceItem{{ID: "E-git-diff", Kind: "git_diff"}})
	for _, claim := range claims {
		if claim.ID == "H-affected-files" {
			if !strings.Contains(claim.Statement, "direct.go") || strings.Contains(claim.Statement, "inferred.go") {
				t.Fatalf("affected-files claim mixed inferred location into supported files: %s", claim.Statement)
			}
			return
		}
	}
	t.Fatal("expected supported affected-files claim")
}

func TestClassifyTimeoutSemantics(t *testing.T) {
	tests := []struct {
		name     string
		attempts []Attempt
		want     Classification
	}{
		{
			name: "all timeouts are inconclusive",
			attempts: []Attempt{
				{Executed: true, TimedOut: true},
				{Executed: true, TimedOut: true},
			},
			want: ClassInconclusive,
		},
		{
			name: "pass and timeout are inconclusive",
			attempts: []Attempt{
				{Executed: true, ExitCode: 0},
				{Executed: true, TimedOut: true},
			},
			want: ClassInconclusive,
		},
		{
			name: "failure and timeout preserve failure",
			attempts: []Attempt{
				{Executed: true, ExitCode: 1, Stderr: "assertion failed"},
				{Executed: true, TimedOut: true},
			},
			want: ClassRealRegression,
		},
		{
			name: "unexecuted attempt is inconclusive",
			attempts: []Attempt{
				{Executed: false},
			},
			want: ClassInconclusive,
		},
		{
			name: "completed failure and pass are flaky",
			attempts: []Attempt{
				{Executed: true, ExitCode: 1},
				{Executed: true, ExitCode: 0},
			},
			want: ClassFlaky,
		},
		{
			name: "completed pass is not reproduced",
			attempts: []Attempt{
				{Executed: true, ExitCode: 0},
			},
			want: ClassNotReproduced,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Classify(test.attempts); got != test.want {
				t.Fatalf("classification = %s, want %s", got, test.want)
			}
		})
	}
}
