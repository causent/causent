package diagnosis

import (
	"encoding/json"
	"testing"

	"github.com/causent/malenia/internal/domain"
)

func TestTerminalInvestigationRecordsUnresolvedAndUnattemptedWork(t *testing.T) {
	report := &Report{
		StoppingReason: "budget_exhausted",
		InvestigationObjective: &InvestigationObjective{Unknowns: []InvestigationUnknown{
			{ID: "exact-memory", Predicate: "same concrete object", Status: "unresolved", RequiredKinds: []string{"source identity"}, Evaluation: "address identity is missing", NextAction: "TraceVariable", CandidateActions: []string{"TraceVariable", "FindReferences"}},
			{ID: "done", Status: "resolved"},
		}},
	}
	ensureTerminalInvestigation(report, report.StoppingReason, domain.InvestigationBudget{MaxActivities: 2, ActivitiesUsed: 2})
	terminal := report.TerminalInvestigation
	if terminal == nil || terminal.Reason != "budget_exhausted" {
		t.Fatalf("missing terminal reason: %#v", terminal)
	}
	if len(terminal.UnresolvedDependencies) != 1 || terminal.UnresolvedDependencies[0].ID != "exact-memory" {
		t.Fatalf("resolved dependency leaked into terminal state: %#v", terminal.UnresolvedDependencies)
	}
	if len(terminal.ActionsNotAttempted) != 2 || terminal.ActionsNotAttempted[0].Status != "excluded_by_budget" {
		t.Fatalf("unattempted work was not classified accurately: %#v", terminal.ActionsNotAttempted)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 {
		t.Fatal("terminal explanation was not machine-readable")
	}
}

func TestTerminalInvestigationMarksUnavailableActions(t *testing.T) {
	report := &Report{InvestigationObjective: &InvestigationObjective{Unknowns: []InvestigationUnknown{
		{ID: "lifecycle", Status: "unresolved", CandidateActions: []string{"InspectGoroutineLifecycle"}},
	}}}
	ensureTerminalInvestigation(report, "execution_unavailable", domain.InvestigationBudget{})
	if len(report.TerminalInvestigation.ActionsNotAttempted) != 1 || report.TerminalInvestigation.ActionsNotAttempted[0].Status != "unavailable" {
		t.Fatalf("unavailable action was not recorded: %#v", report.TerminalInvestigation)
	}
}

func TestAdaptiveActionTargetRequiresSourceLocation(t *testing.T) {
	if got := adaptiveActionTarget(&Report{Candidates: []domain.CandidateLocation{{Location: domain.CodeLocation{SymbolIdentity: "Cacher.Stop"}}}}); got != "" {
		t.Fatalf("target without file location was accepted: %q", got)
	}
	got := adaptiveActionTarget(&Report{Candidates: []domain.CandidateLocation{{Location: domain.CodeLocation{FilePath: "cacher.go", StartLine: 1389, SymbolIdentity: "Cacher.Stop"}}}})
	if got != "cacher.go:1389:Cacher.Stop" {
		t.Fatalf("unexpected source target: %q", got)
	}
}
