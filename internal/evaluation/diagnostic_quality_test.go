package evaluation

import (
	"testing"

	"github.com/causent/malenia/internal/diagnosis"
	"github.com/causent/malenia/internal/domain"
)

func TestMeasureDiagnosticQualitySeparatesLocalizationGroupingAndClaims(t *testing.T) {
	report := diagnosis.Report{
		Localization:  diagnosis.Localization{LikelyFiles: []string{"unchanged.go"}},
		Candidates:    []domain.CandidateLocation{{ID: "c", Location: domain.CodeLocation{FilePath: "unchanged.go", SymbolIdentity: "go:pkg:Function:Shared"}, Score: domain.ScoreVector{AvailableDimensions: []string{"execution"}}}},
		FailureGroups: []domain.FailureGroup{{Status: "potentially_related", FailureIDs: []string{"f1", "f2"}}},
		Evidence:      []diagnosis.EvidenceItem{{ID: "e1"}},
		Claims:        []diagnosis.Claim{{Supporting: []string{"e1", "missing"}}},
	}
	metrics := Measure(report, DiagnosticTruth{RelevantLocations: []string{"unchanged.go"}, FailureGroups: [][]string{{"f1", "f2"}}, Answerable: true}, 5)
	if metrics.Top1Localization != 1 || metrics.UnchangedCodeRecall != 1 || metrics.GroupingPrecision != 1 || metrics.GroupingRecall != 1 || metrics.UnsupportedClaims != 1 || !metrics.FalseDiagnosis {
		t.Fatalf("unexpected quality metrics: %#v", metrics)
	}
}

func TestMeasureDiagnosticQualityRecognizesJustifiedAbstention(t *testing.T) {
	metrics := Measure(diagnosis.Report{Refused: true}, DiagnosticTruth{Answerable: false}, 5)
	if !metrics.CorrectAbstention || metrics.FalseDiagnosis {
		t.Fatalf("unexpected abstention metrics: %#v", metrics)
	}
}
