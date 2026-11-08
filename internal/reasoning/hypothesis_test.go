package reasoning

import (
	"github.com/causent/causent/internal/domain"
	"testing"
	"time"
)

func TestGenerateCompetingHypothesesForOneFailureGroup(t *testing.T) {
	group := domain.FailureGroup{ID: "g", InvestigationID: "inv", FailureIDs: []string{"f1", "f2"}, Status: "potentially_related"}
	candidates := []domain.CandidateLocation{{ID: "c1", Location: domain.CodeLocation{SymbolIdentity: "go:a:Function:One", FilePath: "a.go"}, SupportingEvidenceIDs: []domain.ID{"e1"}}, {ID: "c2", Location: domain.CodeLocation{SymbolIdentity: "go:b:Function:Two", FilePath: "b.go"}, SupportingEvidenceIDs: []domain.ID{"e2"}}}
	hypotheses := Generate("inv", []domain.FailureGroup{group}, candidates)
	if len(hypotheses) != 2 {
		t.Fatalf("hypotheses=%d", len(hypotheses))
	}
	for _, h := range hypotheses {
		if len(h.RelatedFailureIDs) != 2 || h.HypothesisGroupID != "g" {
			t.Fatalf("hypothesis=%#v", h)
		}
	}
}

func TestAssessContradictionAndVersionHistory(t *testing.T) {
	h := domain.Hypothesis{ID: "h", InvestigationID: "inv", Statement: "possible", SupportingEvidenceIDs: []domain.ID{"support"}, ContradictingEvidenceIDs: []domain.ID{"contra"}, Version: 1, CreatedAt: time.Now()}
	evidence := map[domain.ID]domain.Evidence{"support": {ID: "support", InvestigationID: "inv"}, "contra": {ID: "contra", InvestigationID: "inv"}}
	assessed := Assess(h, evidence, nil, nil).Hypothesis
	if assessed.Status != domain.HypWeakened {
		t.Fatalf("status=%s", assessed.Status)
	}
	next := Version(assessed, nil)
	if next.Version != 1 {
		t.Fatalf("version=%d", next.Version)
	}
	next = Version(assessed, &next)
	if next.Version != 2 || next.SupersedesHypothesisID != "h" {
		t.Fatalf("versioned=%#v", next)
	}
}

func TestValidateFindingRejectsForeignRevisionAndEvidence(t *testing.T) {
	f := domain.DiagnosticFinding{ID: "f", InvestigationID: "inv", Statement: "possible", HypothesisID: "h", EvidenceIDs: []domain.ID{"e"}, CandidateIDs: []string{"c"}}
	v := ValidateFinding(f, "inv", map[domain.ID]domain.Evidence{"e": {ID: "e", InvestigationID: "inv"}}, map[domain.ID]domain.Hypothesis{"h": {ID: "h", InvestigationID: "inv"}}, map[string]domain.CandidateLocation{"c": {ID: "c", Location: domain.CodeLocation{RevisionID: "foreign"}}}, map[string]bool{"rev": true})
	if v.Valid {
		t.Fatal("foreign revision accepted")
	}
}
