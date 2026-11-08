package reasoning

import (
	"fmt"
	"github.com/causent/malenia/internal/domain"
	"time"
)

func ValidateFinding(f domain.DiagnosticFinding, investigationID domain.ID, evidence map[domain.ID]domain.Evidence, hypotheses map[domain.ID]domain.Hypothesis, candidates map[string]domain.CandidateLocation, revisions map[string]bool) domain.ClaimValidation {
	v := domain.ClaimValidation{ClaimID: f.ID, Valid: true, ValidatedAt: time.Now().UTC()}
	if f.InvestigationID != investigationID {
		v.Valid = false
		v.Reasons = append(v.Reasons, "finding belongs to another investigation")
	}
	if f.Statement == "" {
		v.Valid = false
		v.Reasons = append(v.Reasons, "empty statement")
	}
	if f.HypothesisID != "" {
		if h, ok := hypotheses[f.HypothesisID]; !ok {
			v.Valid = false
			v.Reasons = append(v.Reasons, "hypothesis reference not found")
		} else if h.InvestigationID != investigationID {
			v.Valid = false
			v.Reasons = append(v.Reasons, "hypothesis belongs to another investigation")
		}
	}
	if len(f.EvidenceIDs) == 0 {
		v.Valid = false
		v.Reasons = append(v.Reasons, "no evidence references")
	}
	for _, id := range f.EvidenceIDs {
		if e, ok := evidence[id]; !ok {
			v.Valid = false
			v.Reasons = append(v.Reasons, fmt.Sprintf("evidence %s not found", id))
		} else if e.InvestigationID != investigationID {
			v.Valid = false
			v.Reasons = append(v.Reasons, fmt.Sprintf("evidence %s belongs to another investigation", id))
		}
	}
	for _, id := range f.CandidateIDs {
		c, ok := candidates[id]
		if !ok {
			v.Valid = false
			v.Reasons = append(v.Reasons, "candidate reference not found")
			continue
		}
		if !revisions[c.Location.RevisionID] {
			v.Valid = false
			v.Reasons = append(v.Reasons, "candidate revision reference not found")
		}
	}
	return v
}
