package diagnosis

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/causent/malenia/internal/localization"
)

func runtimeTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestIngestRuntimeRaceReportsBuildsObservedGraphWithoutCausalClaims(t *testing.T) {
	reports := parseRaceReports(string(runtimeTestFile(t, "testdata/kubernetes-race.log")))
	graph := IngestRuntimeRaceReportsWithProvenance(reports, ExecutionIdentity{ExecutionID: "exec-1", SourceRevision: "rev-1"}, RuntimeArtifactProvenance{ArtifactID: "artifact-1", Digest: "raw-digest", StorageRef: "artifact://race", ParserName: "go-race-report-parser", ParserVersion: "p2.1"})
	if len(graph.Races) != 1 || len(graph.Accesses) != 2 || len(graph.Overlaps) != 1 {
		t.Fatalf("unexpected runtime graph: %#v", graph)
	}
	if graph.Overlaps[0].Relationship != "same_address" || graph.Overlaps[0].AddressA != "0x00c0006135c0" {
		t.Fatalf("same-address observation missing: %#v", graph.Overlaps)
	}
	for _, access := range graph.Accesses {
		if access.SourceAccessID != "" || access.SourceResolutionStatus != "enclosing_function" {
			t.Fatalf("race stack over-resolved source access: %#v", access)
		}
	}
	if len(graph.Accesses[0].GoroutineCreationStack) != 0 || len(graph.Accesses[1].GoroutineCreationStack) < 2 {
		t.Fatalf("creation stack was not associated with write goroutine: %#v", graph.Accesses)
	}
	items := RuntimeEvidenceItems(graph, "artifact://race")
	if items[0].ArtifactID != "artifact-1" || items[0].ArtifactDigest != "raw-digest" || items[0].StorageRef != "artifact://race" || items[0].ParserName != "go-race-report-parser" || items[0].ParserVersion != "p2.1" || items[0].Digest != "raw-digest" {
		t.Fatalf("raw artifact provenance was not preserved: %#v", items[0])
	}
	for _, item := range items {
		if item.ClaimKind == "RuntimeObjectIdentity" || item.ClaimKind == "HappensBefore" || item.Ordering != "" {
			t.Fatalf("runtime ingestion produced forbidden causal claim: %#v", item)
		}
	}
}

func TestCreationStacksFollowGoroutineWhenRaceSectionsReordered(t *testing.T) {
	text := `WARNING: DATA RACE
Previous read at 0x01 by goroutine 32511:
  pkg/read()
      /repo/read.go:10 +0x1
Write at 0x01 by goroutine 31033:
  pkg/write()
      /repo/write.go:20 +0x1
Goroutine 32511 (finished) created at:
  pkg/readCreator()
      /repo/read_creator.go:30 +0x1
Goroutine 31033 (running) created at:
  pkg/writeCreator()
      /repo/write_creator.go:40 +0x1
`
	reports := parseRaceReports(text)
	if len(reports) != 1 {
		t.Fatalf("reports = %d", len(reports))
	}
	graph := IngestRuntimeRaceReportsWithProvenance(reports, ExecutionIdentity{ReportID: "report-1"}, RuntimeArtifactProvenance{ArtifactID: "artifact-1", Digest: "digest-1", StorageRef: "ref-1", ParserName: "go-race-report-parser", ParserVersion: "p2.1"})
	if len(graph.Overlaps) != 1 {
		t.Fatalf("same-report overlap missing: %#v", graph.Overlaps)
	}
	for _, access := range graph.Accesses {
		if access.GoroutineID == 32511 && len(access.GoroutineCreationStack) != 1 || access.GoroutineID == 31033 && len(access.GoroutineCreationStack) != 1 {
			t.Fatalf("creation stack followed section order instead of goroutine: %#v", graph.Accesses)
		}
	}
}

func TestUnknownExecutionCannotCorrelateSeparateReportsOrTraces(t *testing.T) {
	identity := ExecutionIdentity{ReportID: "report-1"}
	graph := RuntimeEvidenceGraph{Execution: identity}
	if err := CorrelateExecutionTrace(&graph, ExecutionTraceObservation{Execution: identity}, nil); err == nil {
		t.Fatal("correlated trace without actual execution identity")
	}
	other := RuntimeEvidenceGraph{Execution: ExecutionIdentity{ReportID: "report-2"}}
	if len(other.Overlaps) != 0 {
		t.Fatal("separate report unexpectedly shared runtime evidence")
	}
}

func TestSourceResolutionStates(t *testing.T) {
	frame := localization.Frame{File: "x.go", Line: 3, Function: "pkg.F"}
	if got := ClassifySourceResolution("access-1", []localization.Frame{frame}, false); got != SourceResolutionExactAccess {
		t.Fatalf("exact state = %q", got)
	}
	if got := ClassifySourceResolution("", []localization.Frame{frame}, false); got != SourceResolutionEnclosingFunction {
		t.Fatalf("function state = %q", got)
	}
	if got := ClassifySourceResolution("", []localization.Frame{{File: "x.go", Line: 3}}, false); got != SourceResolutionLineOnly {
		t.Fatalf("line state = %q", got)
	}
	if got := ClassifySourceResolution("", []localization.Frame{frame}, true); got != SourceResolutionAmbiguous {
		t.Fatalf("ambiguous state = %q", got)
	}
	if got := ClassifySourceResolution("", nil, false); got != SourceResolutionUnresolved {
		t.Fatalf("unresolved state = %q", got)
	}
}

func TestLegacyRuntimeAccessDeserializesWithoutNewFields(t *testing.T) {
	var access RuntimeAccessObservation
	if err := json.Unmarshal([]byte(`{"id":"legacy","operation":"read","source_resolution_status":"enclosing_function_or_line"}`), &access); err != nil {
		t.Fatal(err)
	}
	if access.ID != "legacy" || access.SourceResolutionStatus != "enclosing_function_or_line" || access.Execution.ExecutionID != "" {
		t.Fatalf("legacy runtime observation was not preserved: %#v", access)
	}
}

func TestRuntimeEvidenceIDsMakeDuplicateIngestionIdempotent(t *testing.T) {
	reports := parseRaceReports(string(runtimeTestFile(t, "testdata/kubernetes-race.log")))
	id := ExecutionIdentity{ExecutionID: "exec-1", SourceRevision: "rev-1"}
	first := RuntimeEvidenceItems(IngestRuntimeRaceReports(reports, id, "artifact://race"), "artifact://race")
	second := RuntimeEvidenceItems(IngestRuntimeRaceReports(reports, id, "artifact://race"), "artifact://race")
	if len(first) != len(second) {
		t.Fatalf("duplicate ingestion changed item count: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].ID != second[i].ID || first[i].Digest != second[i].Digest {
			t.Fatalf("duplicate ingestion changed identity: %#v vs %#v", first[i], second[i])
		}
	}
}

func TestRuntimeTraceCorrelationRequiresCompleteMatchingIdentity(t *testing.T) {
	graph := RuntimeEvidenceGraph{Execution: ExecutionIdentity{ExecutionID: "exec-1", BuildID: "build-1", SourceRevision: "rev-1", TestAttemptID: "attempt-1"}}
	trace := ExecutionTraceObservation{Execution: graph.Execution, ArtifactDigest: "digest", ParserVersion: "trace-parser-v1"}
	var events []GoroutineLifecycleObservation
	var err error
	trace, events, err = ParseStructuredTraceObservation([]byte(`{"format_version":"go-trace-adapter-v1","events":[{"goroutine_id":7,"kind":"create","timestamp":3}]}`), trace)
	if err != nil {
		t.Fatal(err)
	}
	if err := CorrelateExecutionTrace(&graph, trace, events); err != nil {
		t.Fatal(err)
	}
	if len(graph.Lifecycle) != 1 || graph.Lifecycle[0].TraceID != "digest" {
		t.Fatalf("trace lifecycle was not preserved: %#v", graph.Lifecycle)
	}
	for _, other := range []ExecutionIdentity{
		{ExecutionID: "exec-2", BuildID: "build-1", SourceRevision: "rev-1", TestAttemptID: "attempt-1"},
		{ExecutionID: "exec-1", BuildID: "build-2", SourceRevision: "rev-1", TestAttemptID: "attempt-1"},
		{ExecutionID: "exec-1", BuildID: "build-1", SourceRevision: "rev-2", TestAttemptID: "attempt-1"},
		{ExecutionID: "exec-1", BuildID: "build-1", SourceRevision: "rev-1", TestAttemptID: "attempt-2"},
	} {
		if err := CorrelateExecutionTrace(&graph, ExecutionTraceObservation{Execution: other}, nil); err == nil {
			t.Fatalf("correlated mismatched execution: %#v", other)
		}
	}
	if err := CorrelateExecutionTrace(&graph, ExecutionTraceObservation{Execution: ExecutionIdentity{ExecutionID: "exec-1"}}, nil); err == nil {
		t.Fatal("correlated incomplete execution identity")
	}
}

func TestRuntimeTraceKeepsRaceAndTraceGoroutineNamespacesSeparate(t *testing.T) {
	graph := RuntimeEvidenceGraph{Execution: ExecutionIdentity{ExecutionID: "exec-1", BuildID: "build-1", SourceRevision: "rev-1", TestAttemptID: "attempt-1"}, Accesses: []RuntimeAccessObservation{{GoroutineID: 7}}}
	trace := ExecutionTraceObservation{Execution: graph.Execution, ArtifactDigest: "digest", ParserVersion: "trace-parser-v1"}
	events := []GoroutineLifecycleObservation{{ID: "trace-event", Execution: graph.Execution, Goroutine: 7, Kind: "create", TraceID: "digest"}}
	if err := CorrelateExecutionTrace(&graph, trace, events); err != nil {
		t.Fatal(err)
	}
	if graph.Accesses[0].GoroutineID != 7 || graph.Lifecycle[0].Goroutine != 7 {
		t.Fatal("observation namespaces were collapsed")
	}
}

func TestParseStructuredTraceRejectsMalformedOrUnsupportedEvents(t *testing.T) {
	meta := ExecutionTraceObservation{Execution: ExecutionIdentity{ExecutionID: "exec-1"}}
	for _, input := range []string{"{}", `{"format_version":"v1","events":[{"kind":"block"}]}`, "not-json"} {
		if _, err := ParseStructuredTrace([]byte(input), meta); err == nil {
			t.Fatalf("accepted malformed trace %q", input)
		}
	}
}

func TestRuntimeEvidenceReportDoesNotPretendTraceProvesOrdering(t *testing.T) {
	trace := ExecutionTraceObservation{Execution: ExecutionIdentity{ExecutionID: "exec-1"}, ArtifactDigest: "d", ArtifactRef: "artifact://trace", ParserVersion: "v1", TraceFormat: "go-trace-adapter-v1"}
	item := RuntimeTraceEvidenceItem(trace)
	if item.ClaimKind != "ExecutionTraceObservation" || item.Ordering != "" || strings.Contains(item.Detail, "happens-before") {
		t.Fatalf("trace item overclaimed ordering: %#v", item)
	}
}
