package localization

import (
	"fmt"
	"github.com/causent/malenia/internal/domain"
	"time"
)

// ValidateFinding checks references and prevents unsupported findings from
// being published as facts. It intentionally does not judge semantic truth.
func ValidateFinding(f domain.DiagnosticFinding, evidence map[domain.ID]domain.Evidence, hypotheses map[domain.ID]domain.Hypothesis) domain.ClaimValidation {
	v := domain.ClaimValidation{ClaimID: f.ID, Valid: true, ValidatedAt: time.Now().UTC()}
	if f.Statement == "" {
		v.Valid = false
		v.Reasons = append(v.Reasons, "empty statement")
	}
	if f.HypothesisID != "" {
		if _, ok := hypotheses[f.HypothesisID]; !ok {
			v.Valid = false
			v.Reasons = append(v.Reasons, "hypothesis reference not found")
		}
	}
	if len(f.EvidenceIDs) == 0 {
		v.Valid = false
		v.Reasons = append(v.Reasons, "finding has no evidence references")
	}
	for _, id := range f.EvidenceIDs {
		if _, ok := evidence[id]; !ok {
			v.Valid = false
			v.Reasons = append(v.Reasons, fmt.Sprintf("evidence reference %s not found", id))
		}
	}
	return v
}
