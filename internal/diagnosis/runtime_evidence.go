package diagnosis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/causent/malenia/internal/localization"
)

// ExecutionIdentity distinguishes a process execution from its CI workflow.
// Empty fields remain unknown; they are never filled by similarity matching.
type ExecutionIdentity struct {
	WorkflowRunID  string `json:"workflow_run_id,omitempty"`
	BuildID        string `json:"build_id,omitempty"`
	ExecutionID    string `json:"execution_id,omitempty"`
	SourceRevision string `json:"source_revision,omitempty"`
	TestAttemptID  string `json:"test_attempt_id,omitempty"`
}

type RuntimeAccessObservation struct {
	ID                         string               `json:"id"`
	Execution                  ExecutionIdentity    `json:"execution"`
	Operation                  string               `json:"operation"`
	Address                    string               `json:"address,omitempty"`
	GoroutineID                int64                `json:"goroutine_id,omitempty"`
	Stack                      []localization.Frame `json:"stack,omitempty"`
	GoroutineCreationStack     []localization.Frame `json:"goroutine_creation_stack,omitempty"`
	SourceAccessID             string               `json:"source_access_id,omitempty"`
	SourceResolutionStatus     string               `json:"source_resolution_status"`
	SourceResolutionProvenance string               `json:"source_resolution_provenance,omitempty"`
	RawArtifactRef             string               `json:"raw_artifact_ref,omitempty"`
}

type RuntimeMemoryLocationOverlap struct {
	ID           string            `json:"id"`
	Execution    ExecutionIdentity `json:"execution"`
	AccessA      string            `json:"access_a"`
	AccessB      string            `json:"access_b"`
	AddressA     string            `json:"address_a"`
	AddressB     string            `json:"address_b"`
	Relationship string            `json:"relationship"` // same_address or byte_range_overlap
	Provenance   string            `json:"provenance"`
}

type ExecutionTraceObservation struct {
	Execution      ExecutionIdentity `json:"execution"`
	GoVersion      string            `json:"go_version,omitempty"`
	TraceFormat    string            `json:"trace_format,omitempty"`
	ArtifactDigest string            `json:"artifact_digest,omitempty"`
	ArtifactRef    string            `json:"artifact_ref,omitempty"`
	ParserVersion  string            `json:"parser_version"`
	CaptureCommand []string          `json:"capture_command,omitempty"`
	Environment    map[string]string `json:"environment,omitempty"`
}

type GoroutineLifecycleObservation struct {
	ID        string               `json:"id"`
	Execution ExecutionIdentity    `json:"execution"`
	Goroutine int64                `json:"goroutine_id"`
	Kind      string               `json:"kind"`
	Timestamp uint64               `json:"timestamp,omitempty"`
	Stack     []localization.Frame `json:"stack,omitempty"`
	TraceID   string               `json:"trace_id"`
}

type RuntimeEvidenceGraph struct {
	Execution ExecutionIdentity               `json:"execution"`
	Races     []RuntimeObservedRace           `json:"races,omitempty"`
	Accesses  []RuntimeAccessObservation      `json:"accesses,omitempty"`
	Overlaps  []RuntimeMemoryLocationOverlap  `json:"memory_location_overlaps,omitempty"`
	Trace     *ExecutionTraceObservation      `json:"trace,omitempty"`
	Lifecycle []GoroutineLifecycleObservation `json:"goroutine_lifecycle,omitempty"`
}

// RuntimeObservedRace is deliberately narrow: it records what the detector
// reported and does not claim object identity or happens-before semantics.
type RuntimeObservedRace struct {
	ID         string            `json:"id"`
	Execution  ExecutionIdentity `json:"execution"`
	Read       string            `json:"read_access"`
	Write      string            `json:"write_access"`
	Provenance string            `json:"provenance"`
}

func IngestRuntimeRaceReports(reports []RaceReport, execution ExecutionIdentity, artifactRef string) RuntimeEvidenceGraph {
	graph := RuntimeEvidenceGraph{Execution: execution}
	seen := map[string]bool{}
	for i, report := range reports {
		read := runtimeAccess(report, "read", report.ReadAddress, report.ReadGoroutineID, report.ReadStack, creationStack(report, 0), execution, artifactRef, i*2)
		write := runtimeAccess(report, "write", report.WriteAddress, report.WriteGoroutineID, report.WriteStack, creationStack(report, 1), execution, artifactRef, i*2+1)
		graph.Accesses = append(graph.Accesses, read, write)
		key := read.ID + "\x00" + write.ID
		if !seen[key] {
			seen[key] = true
			graph.Races = append(graph.Races, RuntimeObservedRace{ID: raceEvidenceID(execution, report, i), Execution: execution, Read: read.ID, Write: write.ID, Provenance: artifactRef})
		}
		if read.Address != "" && read.Address == write.Address && execution.ExecutionID != "" {
			graph.Overlaps = append(graph.Overlaps, RuntimeMemoryLocationOverlap{ID: "overlap:" + read.ID + ":" + write.ID, Execution: execution, AccessA: read.ID, AccessB: write.ID, AddressA: read.Address, AddressB: write.Address, Relationship: "same_address", Provenance: artifactRef})
		}
	}
	return graph
}

func RuntimeEvidenceItems(graph RuntimeEvidenceGraph, rawArtifactRef string) []EvidenceItem {
	var out []EvidenceItem
	for _, race := range graph.Races {
		payload, _ := json.Marshal(race)
		out = append(out, EvidenceItem{ID: race.ID, Kind: "runtime_observed_race", ClaimKind: "RuntimeObservedRace", Basis: "RuntimeObserved", RunID: race.Execution.ExecutionID, ExecutionID: race.Execution.ExecutionID, BuildID: race.Execution.BuildID, SourceRevision: race.Execution.SourceRevision, TestAttemptID: race.Execution.TestAttemptID, Source: "Go race detector", Detail: string(payload), Provenance: rawArtifactRef, Digest: digestBytes(payload)})
	}
	for _, access := range graph.Accesses {
		payload, _ := json.Marshal(access)
		out = append(out, EvidenceItem{ID: access.ID, Kind: "runtime_access_observation", ClaimKind: "RuntimeAccessObservation", Basis: "RuntimeObserved", AccessID: access.SourceAccessID, RunID: access.Execution.ExecutionID, ExecutionID: access.Execution.ExecutionID, BuildID: access.Execution.BuildID, SourceRevision: access.Execution.SourceRevision, TestAttemptID: access.Execution.TestAttemptID, Source: "Go race detector", Detail: string(payload), Provenance: access.RawArtifactRef, Digest: digestBytes(payload)})
	}
	for _, overlap := range graph.Overlaps {
		payload, _ := json.Marshal(overlap)
		out = append(out, EvidenceItem{ID: overlap.ID, Kind: "runtime_memory_location_overlap", ClaimKind: "RuntimeMemoryLocationOverlap", Basis: "RuntimeObserved", RunID: overlap.Execution.ExecutionID, ExecutionID: overlap.Execution.ExecutionID, BuildID: overlap.Execution.BuildID, SourceRevision: overlap.Execution.SourceRevision, TestAttemptID: overlap.Execution.TestAttemptID, Source: "Go race detector", Detail: string(payload), Provenance: overlap.Provenance, Digest: digestBytes(payload), Limitations: []string{"does not establish containing Go object, field identity, allocation identity, synchronization ordering, or happens-before"}})
	}
	return out
}

func RuntimeTraceEvidenceItem(trace ExecutionTraceObservation) EvidenceItem {
	payload, _ := json.Marshal(trace)
	return EvidenceItem{ID: "runtime-trace:" + trace.Execution.ExecutionID + ":" + trace.ArtifactDigest, Kind: "execution_trace_observation", ClaimKind: "ExecutionTraceObservation", Basis: "RuntimeObserved", RunID: trace.Execution.ExecutionID, ExecutionID: trace.Execution.ExecutionID, BuildID: trace.Execution.BuildID, SourceRevision: trace.Execution.SourceRevision, TestAttemptID: trace.Execution.TestAttemptID, ArtifactID: trace.ArtifactRef, ParserVersion: trace.ParserVersion, TraceFormat: trace.TraceFormat, Source: "Go execution trace adapter", Detail: string(payload), Provenance: trace.ArtifactRef, Digest: digestBytes(payload)}
}

func RuntimeLifecycleEvidenceItems(events []GoroutineLifecycleObservation, trace ExecutionTraceObservation) []EvidenceItem {
	out := make([]EvidenceItem, 0, len(events))
	for _, event := range events {
		payload, _ := json.Marshal(event)
		out = append(out, EvidenceItem{ID: event.ID, Kind: "goroutine_lifecycle_observation", ClaimKind: "GoroutineLifecycleObservation", Basis: "RuntimeObserved", RunID: event.Execution.ExecutionID, ExecutionID: event.Execution.ExecutionID, BuildID: event.Execution.BuildID, SourceRevision: event.Execution.SourceRevision, TestAttemptID: event.Execution.TestAttemptID, ArtifactID: trace.ArtifactRef, ParserVersion: trace.ParserVersion, TraceFormat: trace.TraceFormat, Source: "Go execution trace adapter", Detail: string(payload), Provenance: trace.ArtifactRef, Digest: digestBytes(payload)})
	}
	return out
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func runtimeAccess(report RaceReport, op, address string, gid int64, stack, creation []localization.Frame, execution ExecutionIdentity, artifact string, index int) RuntimeAccessObservation {
	status := "unresolved"
	if len(stack) > 0 {
		status = "enclosing_function_or_line"
	}
	return RuntimeAccessObservation{ID: fmt.Sprintf("runtime-access:%s:%d:%s", execution.ExecutionID, index, op), Execution: execution, Operation: op, Address: address, GoroutineID: gid, Stack: append([]localization.Frame(nil), stack...), GoroutineCreationStack: append([]localization.Frame(nil), creation...), SourceResolutionStatus: status, SourceResolutionProvenance: "race_report_stack", RawArtifactRef: artifact}
}

func creationStack(report RaceReport, index int) []localization.Frame {
	if index >= 0 && index < len(report.GoroutineCreationStacks) {
		return report.GoroutineCreationStacks[index]
	}
	return nil
}

func raceEvidenceID(execution ExecutionIdentity, report RaceReport, index int) string {
	sum := sha256.Sum256([]byte(execution.ExecutionID + "\x00" + report.ReadAddress + "\x00" + report.WriteAddress + fmt.Sprint(index)))
	return "runtime-race:" + hex.EncodeToString(sum[:8])
}

func sameExecution(a, b ExecutionIdentity) bool {
	return a.ExecutionID != "" && b.ExecutionID != "" && a.ExecutionID == b.ExecutionID && a.BuildID == b.BuildID && a.SourceRevision == b.SourceRevision && a.TestAttemptID == b.TestAttemptID
}

// CorrelateExecutionTrace refuses to merge artifacts unless all execution
// identity fields needed for safe correlation are present and equal.
func CorrelateExecutionTrace(graph *RuntimeEvidenceGraph, trace ExecutionTraceObservation, lifecycle []GoroutineLifecycleObservation) error {
	if graph == nil || !sameExecution(graph.Execution, trace.Execution) {
		return fmt.Errorf("runtime artifacts belong to different or incomplete executions")
	}
	for _, event := range lifecycle {
		if !sameExecution(graph.Execution, event.Execution) {
			return fmt.Errorf("lifecycle event %q belongs to a different execution", event.ID)
		}
	}
	graph.Trace = &trace
	graph.Lifecycle = append(graph.Lifecycle, lifecycle...)
	return nil
}

// IngestStructuredTrace parses the stable adapter format and joins it only to
// a matching runtime graph. It does not create memory-access or ordering
// claims from trace timestamps.
func IngestStructuredTrace(graph *RuntimeEvidenceGraph, data []byte, meta ExecutionTraceObservation) ([]EvidenceItem, error) {
	parsedMeta, lifecycle, err := ParseStructuredTraceObservation(data, meta)
	if err != nil {
		return nil, err
	}
	if err := CorrelateExecutionTrace(graph, parsedMeta, lifecycle); err != nil {
		return nil, err
	}
	items := []EvidenceItem{RuntimeTraceEvidenceItem(parsedMeta)}
	items = append(items, RuntimeLifecycleEvidenceItems(lifecycle, parsedMeta)...)
	return items, nil
}

// JSONTraceEvent is the stable internal adapter format. Native Go trace
// binaries are intentionally not parsed as text in P2.1.
type JSONTraceEvent struct {
	GoroutineID int64                `json:"goroutine_id"`
	Kind        string               `json:"kind"`
	Timestamp   uint64               `json:"timestamp,omitempty"`
	Stack       []localization.Frame `json:"stack,omitempty"`
}

type JSONTraceDocument struct {
	FormatVersion string           `json:"format_version"`
	Events        []JSONTraceEvent `json:"events"`
}

func ParseStructuredTrace(data []byte, meta ExecutionTraceObservation) ([]GoroutineLifecycleObservation, error) {
	_, events, err := ParseStructuredTraceObservation(data, meta)
	return events, err
}

func ParseStructuredTraceObservation(data []byte, meta ExecutionTraceObservation) (ExecutionTraceObservation, []GoroutineLifecycleObservation, error) {
	var document JSONTraceDocument
	if err := json.Unmarshal(data, &document); err != nil {
		return meta, nil, fmt.Errorf("parse structured execution trace: %w", err)
	}
	if strings.TrimSpace(document.FormatVersion) == "" || len(document.Events) == 0 {
		return meta, nil, fmt.Errorf("structured execution trace has no supported version or events")
	}
	meta.TraceFormat = document.FormatVersion
	out := make([]GoroutineLifecycleObservation, 0, len(document.Events))
	for i, event := range document.Events {
		if event.GoroutineID <= 0 || strings.TrimSpace(event.Kind) == "" {
			return meta, nil, fmt.Errorf("trace event %d is missing goroutine_id or kind", i)
		}
		out = append(out, GoroutineLifecycleObservation{ID: fmt.Sprintf("trace-event:%s:%d", meta.Execution.ExecutionID, i), Execution: meta.Execution, Goroutine: event.GoroutineID, Kind: event.Kind, Timestamp: event.Timestamp, Stack: event.Stack, TraceID: meta.ArtifactDigest})
	}
	return meta, out, nil
}
