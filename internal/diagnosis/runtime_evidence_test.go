package diagnosis

import (
	"os"
	"strings"
	"testing"
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
	graph := IngestRuntimeRaceReports(reports, ExecutionIdentity{ExecutionID: "exec-1", SourceRevision: "rev-1"}, "artifact://race")
	if len(graph.Races) != 1 || len(graph.Accesses) != 2 || len(graph.Overlaps) != 1 {
		t.Fatalf("unexpected runtime graph: %#v", graph)
	}
	if graph.Overlaps[0].Relationship != "same_address" || graph.Overlaps[0].AddressA != "0x00c0006135c0" {
		t.Fatalf("same-address observation missing: %#v", graph.Overlaps)
	}
	for _, access := range graph.Accesses {
		if access.SourceAccessID != "" || access.SourceResolutionStatus != "enclosing_function_or_line" {
			t.Fatalf("race stack over-resolved source access: %#v", access)
		}
	}
	items := RuntimeEvidenceItems(graph, "artifact://race")
	for _, item := range items {
		if item.ClaimKind == "RuntimeObjectIdentity" || item.ClaimKind == "HappensBefore" || item.Ordering != "" {
			t.Fatalf("runtime ingestion produced forbidden causal claim: %#v", item)
		}
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
