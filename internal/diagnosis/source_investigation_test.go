package diagnosis

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/localization"
	"github.com/causent/malenia/internal/persistence"
	programrepo "github.com/causent/malenia/internal/repository"
)

func TestSourceInvestigationPersistsBoundedFactsAndHypothesis(t *testing.T) {
	dir := newRepo(t)
	commit(t, dir, "race source", map[string]string{
		"race.go": `package race

var shared int

func Read() int {
		return shared
}

func Write(value int) {
		shared = value
}
`,
	})
	store, err := persistence.Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	snapshot, err := (programrepo.Analyzer{}).Analyze(context.Background(), dir, "local:test", "revision:test", "head")
	if err != nil {
		t.Fatal(err)
	}
	report := &Report{
		InvestigationID: "source-investigation-test",
		Environment:     Environment{HeadCommit: "head"},
		FailureIncidents: []FailureIncident{{
			Category: "go_data_race",
			ObservedLocations: []IncidentLocation{
				{Access: "read", File: "race.go", Line: 6, Provenance: "direct_stack_frame"},
				{Access: "write", File: "race.go", Line: 10, Provenance: "direct_stack_frame"},
			},
		}},
		RaceReports: []RaceReport{{
			ReadStack:  []localization.Frame{{File: "race.go", Line: 6, Function: "Read"}},
			WriteStack: []localization.Frame{{File: "race.go", Line: 10, Function: "Write"}},
		}},
	}
	d := &Diagnoser{cfg: Config{RepoPath: dir, Store: store}}
	if err := store.SaveInvestigation(domain.Investigation{ID: domain.ID(report.InvestigationID), RepoPath: dir}); err != nil {
		t.Fatal(err)
	}
	if err := d.runSourceInvestigation(context.Background(), report, dir, snapshot, nil, true); err != nil {
		t.Fatal(err)
	}
	if len(report.InvestigationActions) < 6 {
		t.Fatalf("actions=%d, want bounded source actions: %#v", len(report.InvestigationActions), report.InvestigationActions)
	}
	if len(report.Hypotheses) != 1 {
		t.Fatalf("hypotheses=%d, want one source-backed provisional hypothesis: %#v", len(report.Hypotheses), report.Hypotheses)
	}
	hypothesis := report.Hypotheses[0]
	if len(hypothesis.SupportingEvidenceIDs) == 0 || len(hypothesis.PredictedObservations) == 0 || len(hypothesis.MissingEvidence) == 0 {
		t.Fatalf("hypothesis is not evidence-backed and falsifiable: %#v", hypothesis)
	}
	fullFunction := false
	for _, evidence := range report.Evidence {
		if evidence.Kind == "source function" && strings.Contains(evidence.Detail, "return shared") && strings.Contains(evidence.Detail, "func Read") {
			fullFunction = true
		}
	}
	if !fullFunction {
		t.Fatalf("complete enclosing function was not recorded: %#v", report.Evidence)
	}
	activities, err := store.ListActivities(domain.ID(report.InvestigationID))
	if err != nil {
		t.Fatal(err)
	}
	if len(activities) != len(report.InvestigationActions) {
		t.Fatalf("persisted activities=%d, report actions=%d", len(activities), len(report.InvestigationActions))
	}
}
