package evalcorpus

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/causent/malenia/internal/diagnosis"
)

// ScoreCase reads expected.yaml only in the scorer. Runner code receives only
// RunnerInput and therefore cannot accidentally consume ground truth.
func ScoreCase(caseDir string, report diagnosis.Report) (Score, error) {
	metadata, err := loadYAML[Metadata](filepath.Join(caseDir, "metadata.yaml"))
	if err != nil {
		return Score{}, err
	}
	if err := ValidateMetadata(metadata); err != nil {
		return Score{}, err
	}
	expected, err := loadExpected(filepath.Join(caseDir, "expected.yaml"))
	if err != nil {
		return Score{}, err
	}
	if expected.Category != metadata.Category {
		return Score{}, fmt.Errorf("expected category %q does not match metadata category %q", expected.Category, metadata.Category)
	}
	return ScoreReport(filepath.Base(caseDir), report, expected), nil
}

func ScoreReport(caseID string, report diagnosis.Report, expected Expected) Score {
	if expected.ExpectedOutcome == OutcomeInsufficientEvidence {
		if report.Refused {
			return Score{CaseID: caseID, Outcome: JustifiedAbstention, Reason: "the case is annotated as insufficient evidence and Malenia abstained"}
		}
		return Score{CaseID: caseID, Outcome: Wrong, Reason: "the case is annotated as insufficient evidence but Malenia answered"}
	}
	if report.Refused {
		return Score{CaseID: caseID, Outcome: UnjustifiedAbstention, Reason: "the case is answerable but Malenia abstained"}
	}
	if !categoryMatches(report.Classification, expected.Category) {
		return Score{CaseID: caseID, Outcome: Wrong, Reason: fmt.Sprintf("classification %q does not match expected category %q", report.Classification, expected.Category)}
	}
	if !hasSupportedClaim(report) {
		return Score{CaseID: caseID, Outcome: Wrong, Reason: "answer has no supporting evidence IDs"}
	}
	if expected.CulpritFile != "" && !contains(report.Localization.LikelyFiles, expected.CulpritFile) {
		return Score{CaseID: caseID, Outcome: Wrong, Reason: "expected culprit file was not localized"}
	}
	if expected.CulpritCommit != "" && !containsCommit(report, expected.CulpritCommit) {
		return Score{CaseID: caseID, Outcome: Wrong, Reason: "expected culprit commit was not localized"}
	}
	return Score{CaseID: caseID, Outcome: Correct, Reason: "classification and available attribution match with cited evidence"}
}

func ScoreCorpus(root string, reports map[string]diagnosis.Report) (Counts, []Score, error) {
	if err := CheckFreeze(root); err != nil {
		return Counts{}, nil, err
	}
	_, cases, err := Load(root)
	if err != nil {
		return Counts{}, nil, err
	}
	var counts Counts
	scores := make([]Score, 0, len(cases))
	for _, c := range cases {
		report, ok := reports[c.Metadata.ID]
		if !ok {
			return Counts{}, nil, fmt.Errorf("missing result for case %s", c.Metadata.ID)
		}
		score, err := ScoreCase(c.Dir, report)
		if err != nil {
			return Counts{}, nil, fmt.Errorf("case %s: %w", c.Metadata.ID, err)
		}
		scores = append(scores, score)
		counts.Add(score)
	}
	return counts, scores, nil
}

func hasSupportedClaim(report diagnosis.Report) bool {
	known := map[string]bool{}
	for _, e := range report.Evidence {
		known[e.ID] = true
	}
	for _, claim := range report.Claims {
		if len(claim.Supporting) == 0 {
			continue
		}
		valid := true
		for _, id := range claim.Supporting {
			if !known[id] {
				valid = false
				break
			}
		}
		if valid {
			return true
		}
	}
	return false
}

func categoryMatches(classification diagnosis.Classification, expected Category) bool {
	want := map[Category]diagnosis.Classification{
		CategoryPreExisting:    diagnosis.ClassPreExisting,
		CategoryRegression:     diagnosis.ClassRealRegression,
		CategoryDependency:     diagnosis.ClassDependencyDrift,
		CategoryFlaky:          diagnosis.ClassFlaky,
		CategoryInfrastructure: diagnosis.ClassInfrastructure,
		CategoryNotReproduced:  diagnosis.ClassNotReproduced,
	}
	return want[expected] == classification
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsCommit(report diagnosis.Report, target string) bool {
	for _, commit := range report.Localization.CandidateCommit {
		if strings.HasPrefix(commit.SHA, target) || strings.HasPrefix(target, commit.SHA) {
			return true
		}
	}
	return strings.HasPrefix(report.Localization.FirstKnownBad, target) || strings.HasPrefix(target, report.Localization.FirstKnownBad)
}

// ValidateExpectedFile is intentionally exposed only for scorer-focused tests
// and tooling; it does not create RunnerInput or expose expected data to a
// runner.
func ValidateExpectedFile(path string) error {
	_, err := loadExpected(path)
	return err
}
