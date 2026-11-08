package localization

import (
	"github.com/causent/causent/internal/domain"
	"sort"
)

// Signal names are stable so reports can explain ranking decisions.
const PolicyVersion = "vector-v1"

type Weights struct {
	Execution, Change, Dependency, Behavioural, Historical, Runtime float64
}

var DefaultWeights = Weights{Execution: 6, Change: 4, Dependency: 3, Behavioural: 5, Historical: 2, Runtime: 4}

func Rank(candidates []domain.CandidateLocation, weights Weights) []domain.CandidateLocation {
	out := append([]domain.CandidateLocation(nil), candidates...)
	sort.SliceStable(out, func(i, j int) bool { return Aggregate(out[i].Score, weights) > Aggregate(out[j].Score, weights) })
	return out
}

// Aggregate is a prioritization value, never a probability. Unavailable
// dimensions are omitted from the denominator rather than treated as zero.
func Aggregate(v domain.ScoreVector, w Weights) float64 {
	values := map[string]float64{
		"execution":   v.ExecutionRelevance * w.Execution,
		"change":      v.ChangeRelevance * w.Change,
		"dependency":  v.DependencyRelevance * w.Dependency,
		"behavioural": v.BehaviouralRelevance * w.Behavioural,
		"historical":  v.HistoricalRelevance * w.Historical,
		"runtime":     v.RuntimeRelevance * w.Runtime,
	}
	weights := map[string]float64{"execution": w.Execution, "change": w.Change, "dependency": w.Dependency, "behavioural": w.Behavioural, "historical": w.Historical, "runtime": w.Runtime}
	available := map[string]bool{}
	for _, name := range v.AvailableDimensions {
		available[name] = true
	}
	var total, denominator float64
	for name, value := range values {
		if available[name] {
			total += value
			denominator += weights[name]
		}
	}
	if denominator == 0 {
		return 0
	}
	return total / denominator
}

func Explain(v domain.ScoreVector) []string {
	var out []string
	for _, d := range v.AvailableDimensions {
		var value float64
		switch d {
		case "execution":
			value = v.ExecutionRelevance
		case "change":
			value = v.ChangeRelevance
		case "dependency":
			value = v.DependencyRelevance
		case "behavioural":
			value = v.BehaviouralRelevance
		case "historical":
			value = v.HistoricalRelevance
		case "runtime":
			value = v.RuntimeRelevance
		}
		out = append(out, d+" relevance="+format(value))
	}
	return out
}

// ApplyRuntimeEvidence records execution evidence without fabricating values
// for the other ranking dimensions. It is deliberately monotonic: a later
// experiment can make runtime relevance visible, but never erases provenance.
func ApplyRuntimeEvidence(candidates []domain.CandidateLocation, evidenceIDs []domain.ID) []domain.CandidateLocation {
	out := append([]domain.CandidateLocation(nil), candidates...)
	for i := range out {
		out[i].Score.RuntimeRelevance = 1
		if !containsDimension(out[i].Score.AvailableDimensions, "runtime") {
			out[i].Score.AvailableDimensions = append(out[i].Score.AvailableDimensions, "runtime")
		}
		if out[i].Score.EvidenceByDimension == nil {
			out[i].Score.EvidenceByDimension = map[string][]domain.ID{}
		}
		out[i].Score.EvidenceByDimension["runtime"] = appendUniqueIDs(out[i].Score.EvidenceByDimension["runtime"], evidenceIDs...)
		out[i].Score.ScoringPolicyVersion = PolicyVersion
	}
	return Rank(out, DefaultWeights)
}

// ApplyHistoricalEvidence makes historical retrieval visible as its own
// ranking dimension. It never changes execution, change, or causal claims.
func ApplyHistoricalEvidence(candidates []domain.CandidateLocation, evidenceIDs []domain.ID) []domain.CandidateLocation {
	out := append([]domain.CandidateLocation(nil), candidates...)
	for i := range out {
		out[i].Score.HistoricalRelevance = 1
		if !containsDimension(out[i].Score.AvailableDimensions, "historical") {
			out[i].Score.AvailableDimensions = append(out[i].Score.AvailableDimensions, "historical")
		}
		if out[i].Score.EvidenceByDimension == nil {
			out[i].Score.EvidenceByDimension = map[string][]domain.ID{}
		}
		out[i].Score.EvidenceByDimension["historical"] = appendUniqueIDs(out[i].Score.EvidenceByDimension["historical"], evidenceIDs...)
		out[i].Score.ScoringPolicyVersion = PolicyVersion
	}
	return Rank(out, DefaultWeights)
}

func containsDimension(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func appendUniqueIDs(values []domain.ID, extra ...domain.ID) []domain.ID {
	seen := map[domain.ID]bool{}
	for _, value := range values {
		seen[value] = true
	}
	for _, value := range extra {
		if value != "" && !seen[value] {
			values = append(values, value)
			seen[value] = true
		}
	}
	return values
}

func format(v float64) string { // avoid fmt in report-facing helper's hot path
	if v <= 0 {
		return "0"
	}
	if v >= 1 {
		return "1"
	}
	return "partial"
}
