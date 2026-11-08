package evaluation

import (
	"sort"

	"github.com/causent/causent/internal/diagnosis"
)

// DiagnosticTruth is evaluation-only data. It must never be passed to a
// diagnosis runner or persisted as investigation evidence.
type DiagnosticTruth struct {
	RelevantLocations []string
	FailureGroups     [][]string
	Answerable        bool
}

type DiagnosticQuality struct {
	Top1Localization       float64 `json:"top1_localization"`
	TopKLocalizationRecall float64 `json:"top_k_localization_recall"`
	MeanReciprocalRank     float64 `json:"mean_reciprocal_rank"`
	GroupingPrecision      float64 `json:"grouping_precision"`
	GroupingRecall         float64 `json:"grouping_recall"`
	UnchangedCodeRecall    float64 `json:"unchanged_code_recall"`
	UnsupportedClaims      int     `json:"unsupported_claims"`
	FalseDiagnosis         bool    `json:"false_diagnosis"`
	CorrectAbstention      bool    `json:"correct_abstention"`
}

// Measure computes interpretable case-level metrics without treating ranking
// as causal proof. A relevant location may be represented by a file path or a
// symbol identity in the report's candidates.
func Measure(report diagnosis.Report, truth DiagnosticTruth, topK int) DiagnosticQuality {
	if topK <= 0 {
		topK = 5
	}
	metrics := DiagnosticQuality{CorrectAbstention: !truth.Answerable && report.Refused}
	ordered := append([]string(nil), report.Localization.LikelyFiles...)
	for _, candidate := range report.Candidates {
		ordered = append(ordered, candidate.Location.FilePath, candidate.Location.SymbolIdentity)
	}
	seen := map[string]bool{}
	unique := ordered[:0]
	for _, value := range ordered {
		if value != "" && !seen[value] {
			seen[value] = true
			unique = append(unique, value)
		}
	}
	ordered = unique
	first := 0
	for i, value := range ordered {
		if containsAny(truth.RelevantLocations, value) {
			first = i + 1
			break
		}
	}
	if first == 1 {
		metrics.Top1Localization = 1
	}
	if first > 0 {
		metrics.MeanReciprocalRank = 1 / float64(first)
	}
	limit := topK
	if limit > len(ordered) {
		limit = len(ordered)
	}
	for _, value := range ordered[:limit] {
		if containsAny(truth.RelevantLocations, value) {
			metrics.TopKLocalizationRecall = 1
			break
		}
	}
	if len(truth.RelevantLocations) > 0 {
		for _, location := range truth.RelevantLocations {
			if containsAny(ordered, location) && isUnchanged(report, location) {
				metrics.UnchangedCodeRecall = 1
				break
			}
		}
	}
	actual := actualPairs(report)
	expected := expectedPairs(truth.FailureGroups)
	metrics.GroupingPrecision, metrics.GroupingRecall = pairMetrics(actual, expected)
	known := map[string]bool{}
	for _, evidence := range report.Evidence {
		known[evidence.ID] = true
	}
	for _, claim := range report.Claims {
		for _, evidenceID := range append(append([]string{}, claim.Supporting...), claim.Contradicting...) {
			if !known[evidenceID] {
				metrics.UnsupportedClaims++
			}
		}
	}
	metrics.FalseDiagnosis = truth.Answerable && !report.Refused && (metrics.UnsupportedClaims > 0 || (len(truth.RelevantLocations) > 0 && metrics.TopKLocalizationRecall == 0))
	return metrics
}

func containsAny(values []string, target string) bool {
	for _, value := range values {
		if value == target || (value != "" && target != "" && (len(value) > len(target) && contains(value, target) || len(target) > len(value) && contains(target, value))) {
			return true
		}
	}
	return false
}
func contains(value, target string) bool {
	for i := 0; i+len(target) <= len(value); i++ {
		if value[i:i+len(target)] == target {
			return true
		}
	}
	return false
}
func isUnchanged(report diagnosis.Report, location string) bool {
	for _, candidate := range report.Candidates {
		if candidate.Location.FilePath == location || candidate.Location.SymbolIdentity == location {
			for _, dimension := range candidate.Score.AvailableDimensions {
				if dimension == "change" && candidate.Score.ChangeRelevance > 0 {
					return false
				}
			}
			return true
		}
	}
	return false
}
func expectedPairs(groups [][]string) map[string]bool {
	pairs := map[string]bool{}
	for _, group := range groups {
		sort.Strings(group)
		for i := range group {
			for j := i + 1; j < len(group); j++ {
				pairs[pair(group[i], group[j])] = true
			}
		}
	}
	return pairs
}
func actualPairs(report diagnosis.Report) map[string]bool {
	pairs := map[string]bool{}
	for _, group := range report.FailureGroups {
		if group.Status == "independent" {
			continue
		}
		sort.Strings(group.FailureIDs)
		for i := range group.FailureIDs {
			for j := i + 1; j < len(group.FailureIDs); j++ {
				pairs[pair(group.FailureIDs[i], group.FailureIDs[j])] = true
			}
		}
	}
	return pairs
}
func pair(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "\x00" + b
}
func pairMetrics(actual, expected map[string]bool) (float64, float64) {
	if len(actual) == 0 && len(expected) == 0 {
		return 1, 1
	}
	truePositive := 0
	for value := range actual {
		if expected[value] {
			truePositive++
		}
	}
	precision, recall := 0.0, 0.0
	if len(actual) > 0 {
		precision = float64(truePositive) / float64(len(actual))
	}
	if len(expected) > 0 {
		recall = float64(truePositive) / float64(len(expected))
	}
	return precision, recall
}
