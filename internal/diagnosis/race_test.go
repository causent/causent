package diagnosis

import (
	"os"
	"strings"
	"testing"

	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/localization"
)

func TestParseRaceReportsPreservesReadWriteAndCreationStacks(t *testing.T) {
	data, err := os.ReadFile("testdata/kubernetes-race.log")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	reports := parseRaceReports(text)
	if len(reports) != 1 || len(reports[0].ReadStack) != 1 || len(reports[0].WriteStack) != 1 {
		t.Fatalf("race sides were collapsed: %#v", reports)
	}
	if reports[0].ReadStack[0].Line != 496 || reports[0].WriteStack[0].Line != 187 {
		t.Fatalf("wrong race locations: %#v", reports[0])
	}
	if len(reports[0].GoroutineCreationStacks) != 1 || len(reports[0].GoroutineCreationStacks[0]) < 2 {
		t.Fatalf("creation stack missing: %#v", reports[0])
	}
	if len(reports[0].WriteStack) == 0 || len(reports[0].ReadStack) == 0 || reports[0].WriteStack[0].File == reports[0].ReadStack[0].File {
		t.Fatalf("read/write stacks were not preserved independently: %#v", reports[0])
	}
	for _, frame := range append(reports[0].WriteStack, reports[0].ReadStack...) {
		if frame.File == "logger.go" || frame.File == "feature_gate.go" || frame.File == "sorted_test.go" {
			t.Fatalf("non-stack log line accepted as frame: %#v", frame)
		}
	}
	if reports[0].Test != "TestWatch/WatchCacheStallResume=true/WatchWithoutPrevKV=true/ClusterScopedWatch" || reports[0].ReadAccessType != "read" || reports[0].WriteAccessType != "write" {
		t.Fatalf("race metadata missing: %#v", reports[0])
	}
}

func TestParseRun43RaceFixtureRejectsTestOutputAndFilenameMatches(t *testing.T) {
	data, err := os.ReadFile("testdata/kubernetes-run43-race.log")
	if err != nil {
		t.Fatal(err)
	}
	reports := parseRaceReports(string(data))
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want one: %#v", len(reports), reports)
	}
	race := reports[0]
	if len(race.ReadStack) != 1 || len(race.WriteStack) != 7 {
		t.Fatalf("unexpected access stack sizes: read=%d write=%d", len(race.ReadStack), len(race.WriteStack))
	}
	if len(race.GoroutineCreationStacks) != 2 || len(race.GoroutineCreationStacks[0]) != 5 || len(race.GoroutineCreationStacks[1]) != 7 {
		t.Fatalf("unexpected creation stacks: %#v", race.GoroutineCreationStacks)
	}
	for _, stack := range append(append([]localization.Frame{}, race.ReadStack...), race.WriteStack...) {
		if strings.Contains(stack.File, "logger.go") || strings.Contains(stack.File, "feature_gate.go") || strings.Contains(stack.File, "sorted_test.go") || strings.HasPrefix(stack.Function, "=== ") {
			t.Fatalf("non-stack output parsed as access frame: %#v", stack)
		}
	}
	for _, stack := range race.GoroutineCreationStacks {
		for _, frame := range stack {
			if frame.File == "logger.go" || frame.File == "feature_gate.go" || frame.File == "sorted_test.go" || strings.HasPrefix(frame.Function, "=== ") {
				t.Fatalf("non-stack output parsed as creation frame: %#v", frame)
			}
		}
	}
	if race.ReadStack[0].LogLine == 0 || race.WriteStack[0].LogLine == 0 {
		t.Fatal("original CI line references were not preserved")
	}
}

func TestRun43FixtureBuildsOneIncidentForItsAffectedTests(t *testing.T) {
	data, err := os.ReadFile("testdata/kubernetes-run43-race.log")
	if err != nil {
		t.Fatal(err)
	}
	reports := parseRaceReports(string(data))
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want one", len(reports))
	}
	report := &Report{
		Classification:  ClassTestFailureObserved,
		FailureEpisodes: []domain.FailureEpisode{{TestIdentifier: reports[0].Test}},
		RaceReports:     reports,
	}
	incidents := buildFailureIncidents(report)
	if len(incidents) != 1 {
		t.Fatalf("incidents = %d, want one: %#v", len(incidents), incidents)
	}
	if len(incidents[0].AffectedTests) != 1 || incidents[0].AffectedTests[0] != reports[0].Test {
		t.Fatalf("affected tests were not grouped under the incident: %#v", incidents[0])
	}
	if strings.Contains(incidents[0].ObservedExplanation, "during .") || incidents[0].CausalityConfidence != 0 {
		t.Fatalf("incident overclaimed or malformed context: %#v", incidents[0])
	}
}

func TestParseRaceReportsHandlesMultipleAndIncompleteReports(t *testing.T) {
	text := `WARNING: DATA RACE
Read at 0x00 by goroutine 1:
  pkg/a()
      /workspace/a.go:10 +0x1
Previous write at 0x00 by goroutine 2:
  pkg/b()
      /workspace/b.go:20 +0x1
WARNING: DATA RACE
Read at 0x00 by goroutine 3:
  pkg/c()
`
	reports := parseRaceReports(text)
	if len(reports) != 2 {
		t.Fatalf("reports = %d, want 2: %#v", len(reports), reports)
	}
	if len(reports[1].ReadStack) != 0 {
		t.Fatalf("incomplete location invented: %#v", reports[1])
	}
}

func TestBuildFailureIncidentGroupsRaceAffectedTestsWithoutCausalOverclaim(t *testing.T) {
	report := &Report{
		Classification: ClassTestFailureObserved,
		FailureEpisodes: []domain.FailureEpisode{
			{TestIdentifier: "TestWatch/One"},
			{TestIdentifier: "TestWatch/Two"},
		},
		RaceReports: []RaceReport{{Test: "TestWatch", ReadStack: []localization.Frame{{File: "cacher.go", Line: 496, Function: "NewCacherFromConfig"}}, WriteStack: []localization.Frame{{File: "setup.go", Line: 187, Function: "SetupWithCacher"}}}},
	}
	incidents := buildFailureIncidents(report)
	if len(incidents) != 1 || len(incidents[0].AffectedTests) != 2 {
		t.Fatalf("incident did not group affected tests: %#v", incidents)
	}
	if incidents[0].CausalityConfidence != 0 || incidents[0].ObservedConfidence != 1 {
		t.Fatalf("confidence overclaims causality: %#v", incidents[0])
	}
}

func TestBuildFailureIncidentOmitsUnknownExecutionContext(t *testing.T) {
	report := &Report{
		Classification:  ClassTestFailureObserved,
		FailureEpisodes: []domain.FailureEpisode{{TestIdentifier: "TestWatch/One"}},
		RaceReports:     []RaceReport{{ReadStack: []localization.Frame{{File: "cacher.go", Line: 496}}, WriteStack: []localization.Frame{{File: "setup.go", Line: 187}}}},
	}
	incidents := buildFailureIncidents(report)
	if len(incidents) != 1 || strings.Contains(incidents[0].ObservedExplanation, "during .") {
		t.Fatalf("malformed unknown execution context: %#v", incidents)
	}
}

func TestRaceIncidentLeavesRootCauseUnknown(t *testing.T) {
	report := Report{
		FailureIncidents: []FailureIncident{{
			Category: "go_data_race",
			ObservedLocations: []IncidentLocation{
				{Access: "read", File: "cacher.go", Line: 496, Provenance: "direct_stack_frame"},
				{Access: "write", File: "setup.go", Line: 187, Provenance: "direct_stack_frame"},
			},
			EvidenceIDs: []string{"ci-race"},
		}},
	}
	assessment := assessRootCause(report)
	if assessment.Status != "unknown" || assessment.CausalityStatus != "unverified" || assessment.VerificationStatus != "not_attempted" {
		t.Fatalf("race root cause was overclaimed: %#v", assessment)
	}
	if len(assessment.ObservedLocations) != 2 || len(assessment.EvidenceIDs) != 1 {
		t.Fatalf("root cause assessment lost incident provenance: %#v", assessment)
	}
}
