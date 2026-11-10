// Package reasoning generates and assesses open-world hypotheses from
// structured evidence. It never promotes candidate ranking to causality.
package reasoning

import (
	"fmt"
	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/localization"
	"sort"
	"time"
)

type Assessment struct {
	Hypothesis      domain.Hypothesis
	MissingEvidence []string
}

func Generate(inv domain.ID, groups []domain.FailureGroup, candidates []domain.CandidateLocation) []domain.Hypothesis {
	byCandidate := map[string]domain.CandidateLocation{}
	for _, c := range candidates {
		byCandidate[c.ID] = c
	}
	var out []domain.Hypothesis
	for _, group := range groups {
		used := map[string]bool{}
		for _, c := range candidates {
			if len(group.CandidateIDs) > 0 && !containsString(group.CandidateIDs, c.ID) {
				continue
			}
			if used[c.ID] {
				continue
			}
			statement := fmt.Sprintf("Candidate location %s may explain the observed failure episode(s) %s", c.Location.SymbolIdentity, join(group.FailureIDs))
			id := domain.ID("hypothesis:" + c.ID + ":" + group.ID)
			h := domain.Hypothesis{ID: id, InvestigationID: inv, HypothesisGroupID: domain.ID(group.ID), Version: 1, Statement: statement, AffectedComponent: c.Location.FilePath + ":" + fmt.Sprint(c.Location.StartLine), RelatedFailureIDs: append([]string{}, group.FailureIDs...), CandidateLocationIDs: []string{c.ID}, SupportingEvidenceIDs: append([]domain.ID{}, c.SupportingEvidenceIDs...), Status: domain.HypProposed, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Provenance: "deterministic candidate and relationship evidence", Relevance: localization.Aggregate(c.Score, localization.DefaultWeights)}
			h.Confidence = hypothesisEvidenceConfidence(c)
			out = append(out, h)
			used[c.ID] = true
			if len(out) > 100 {
				break
			}
		}
	}
	// Competing explanations are explicit, even when they refer to different
	// locations in the same failure group.
	byGroup := map[domain.ID][]domain.ID{}
	for _, h := range out {
		byGroup[h.HypothesisGroupID] = append(byGroup[h.HypothesisGroupID], h.ID)
	}
	for i := range out {
		if len(byGroup[out[i].HypothesisGroupID]) > 1 {
			out[i].PredictedObservations = []string{"Evidence or an experiment should distinguish this candidate from competing explanations"}
		}
	}
	_ = byCandidate
	return out
}

func hypothesisEvidenceConfidence(c domain.CandidateLocation) float64 {
	confidence := 0.25
	if c.Score.ExecutionRelevance > 0 {
		confidence += 0.15
	}
	if c.Score.BehaviouralRelevance > 0 {
		confidence += 0.1
	}
	if c.Score.ChangeRelevance > 0 {
		confidence += 0.05
	}
	if confidence > 0.6 {
		return 0.6
	}
	return confidence
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func Assess(h domain.Hypothesis, evidence map[domain.ID]domain.Evidence, contradictions map[domain.ID][]domain.ID, experiments map[domain.ID]domain.Experiment) Assessment {
	missing := []string{}
	support := 0
	for _, id := range h.SupportingEvidenceIDs {
		if _, ok := evidence[id]; ok {
			support++
		} else {
			missing = append(missing, "supporting evidence "+string(id)+" is unavailable")
		}
	}
	contradict := 0
	for _, id := range h.ContradictingEvidenceIDs {
		if _, ok := evidence[id]; ok {
			contradict++
		} else {
			missing = append(missing, "contradicting evidence "+string(id)+" is unavailable")
		}
	}
	for _, ids := range contradictions {
		for _, id := range ids {
			if _, ok := evidence[id]; ok {
				contradict++
			}
		}
	}
	if contradict > 0 {
		h.Status = domain.HypWeakened
	}
	if support == 0 && contradict == 0 {
		h.Status = domain.HypInconclusive
		missing = append(missing, "no validated supporting evidence")
	}
	if support > 0 && contradict == 0 {
		h.Status = domain.HypUnderInvestigation
	}
	for _, ex := range experiments {
		if ex.Outcome == domain.OutcomeSupports {
			h.Status = domain.HypSupported
		}
		if ex.Outcome == domain.OutcomeContradicts {
			h.Status = domain.HypContradicted
		}
	}
	h.MissingEvidence = missing
	h.UpdatedAt = time.Now().UTC()
	return Assessment{Hypothesis: h, MissingEvidence: missing}
}

func Version(next domain.Hypothesis, previous *domain.Hypothesis) domain.Hypothesis {
	if previous == nil {
		if next.Version <= 0 {
			next.Version = 1
		}
		return next
	}
	next.Version = previous.Version + 1
	next.SupersedesHypothesisID = previous.ID
	next.HypothesisGroupID = previous.HypothesisGroupID
	// Each revision is a durable entity. The supersession link preserves the
	// chain while allowing historical assessments to remain immutable.
	next.ID = domain.ID(fmt.Sprintf("%s:v%d", previous.ID, next.Version))
	return next
}
func join(ids []string) string {
	cp := append([]string{}, ids...)
	sort.Strings(cp)
	return fmt.Sprintf("%v", cp)
}
