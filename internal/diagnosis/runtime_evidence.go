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
	ReportID       string `json:"report_id,omitempty"`
	BuildID        string `json:"build_id,omitempty"`
	ExecutionID    string `json:"execution_id,omitempty"`
	SourceRevision string `json:"source_revision,omitempty"`
	TestAttemptID  string `json:"test_attempt_id,omitempty"`
}

type RuntimeArtifactProvenance struct {
	ArtifactID    string `json:"artifact_id,omitempty"`
	Digest        string `json:"digest,omitempty"`
	StorageRef    string `json:"storage_ref,omitempty"`
	ParserName    string `json:"parser_name,omitempty"`
	ParserVersion string `json:"parser_version,omitempty"`
}

const (
	SourceResolutionExactAccess       = "exact_access"
	SourceResolutionEnclosingFunction = "enclosing_function"
	SourceResolutionLineOnly          = "line_only"
	SourceResolutionAmbiguous         = "ambiguous"
	SourceResolutionUnresolved        = "unresolved"
)

func ClassifySourceResolution(accessID string, stack []localization.Frame, ambiguous bool) string {
	if accessID != "" {
		return SourceResolutionExactAccess
	}
	if ambiguous {
		return SourceResolutionAmbiguous
	}
	if len(stack) == 0 {
		return SourceResolutionUnresolved
	}
	if stack[0].Function != "" {
		return SourceResolutionEnclosingFunction
	}
	if stack[0].File != "" && stack[0].Line > 0 {
		return SourceResolutionLineOnly
	}
	return SourceResolutionUnresolved
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
	RawArtifactID              string               `json:"raw_artifact_id,omitempty"`
	RawArtifactDigest          string               `json:"raw_artifact_digest,omitempty"`
	ParserName                 string               `json:"parser_name,omitempty"`
	ParserVersion              string               `json:"parser_version,omitempty"`
}

type RuntimeMemoryLocationOverlap struct {
	ID           string                    `json:"id"`
	Execution    ExecutionIdentity         `json:"execution"`
	AccessA      string                    `json:"access_a"`
	AccessB      string                    `json:"access_b"`
	AddressA     string                    `json:"address_a"`
	AddressB     string                    `json:"address_b"`
	Relationship string                    `json:"relationship"` // same_address or byte_range_overlap
	Provenance   string                    `json:"provenance"`
	Artifact     RuntimeArtifactProvenance `json:"artifact"`
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
	Artifact  RuntimeArtifactProvenance       `json:"artifact,omitempty"`
	Races     []RuntimeObservedRace           `json:"races,omitempty"`
	Accesses  []RuntimeAccessObservation      `json:"accesses,omitempty"`
	Overlaps  []RuntimeMemoryLocationOverlap  `json:"memory_location_overlaps,omitempty"`
	Trace     *ExecutionTraceObservation      `json:"trace,omitempty"`
	Lifecycle []GoroutineLifecycleObservation `json:"goroutine_lifecycle,omitempty"`
}

// RuntimeObservedRace is deliberately narrow: it records what the detector
// reported and does not claim object identity or happens-before semantics.
type RuntimeObservedRace struct {
	ID         string                    `json:"id"`
	Execution  ExecutionIdentity         `json:"execution"`
	Read       string                    `json:"read_access"`
	Write      string                    `json:"write_access"`
	Provenance string                    `json:"provenance"`
	Artifact   RuntimeArtifactProvenance `json:"artifact"`
}

func IngestRuntimeRaceReports(reports []RaceReport, execution ExecutionIdentity, artifactRef string) RuntimeEvidenceGraph {
	return ingestRuntimeRaceReports(reports, execution, RuntimeArtifactProvenance{StorageRef: artifactRef, ParserName: "go-race-report", ParserVersion: "unknown"})
}

func IngestRuntimeRaceReportsWithProvenance(reports []RaceReport, execution ExecutionIdentity, artifact RuntimeArtifactProvenance) RuntimeEvidenceGraph {
	return ingestRuntimeRaceReports(reports, execution, artifact)
}

func ingestRuntimeRaceReports(reports []RaceReport, execution ExecutionIdentity, artifact RuntimeArtifactProvenance) RuntimeEvidenceGraph {
	graph := RuntimeEvidenceGraph{Execution: execution, Artifact: artifact}
	seen := map[string]bool{}
	for i, report := range reports {
		read := runtimeAccess(report, "read", report.ReadAddress, report.ReadGoroutineID, report.ReadStack, creationStack(report, report.ReadGoroutineID), execution, artifact, i*2)
		write := runtimeAccess(report, "write", report.WriteAddress, report.WriteGoroutineID, report.WriteStack, creationStack(report, report.WriteGoroutineID), execution, artifact, i*2+1)
		graph.Accesses = append(graph.Accesses, read, write)
		key := read.ID + "\x00" + write.ID
		if !seen[key] {
			seen[key] = true
			graph.Races = append(graph.Races, RuntimeObservedRace{ID: raceEvidenceID(execution, report, i), Execution: execution, Read: read.ID, Write: write.ID, Provenance: artifact.StorageRef, Artifact: artifact})
		}
		if read.Address != "" && read.Address == write.Address && (execution.ExecutionID != "" || execution.ReportID != "") {
			graph.Overlaps = append(graph.Overlaps, RuntimeMemoryLocationOverlap{ID: "overlap:" + read.ID + ":" + write.ID, Execution: execution, AccessA: read.ID, AccessB: write.ID, AddressA: read.Address, AddressB: write.Address, Relationship: "same_address", Provenance: artifact.StorageRef, Artifact: artifact})
		}
	}
	return graph
}

func RuntimeEvidenceItems(graph RuntimeEvidenceGraph, rawArtifactRef string) []EvidenceItem {
	var out []EvidenceItem
	for _, race := range graph.Races {
		payload, _ := json.Marshal(race)
		out = append(out, runtimeEvidenceItem(race.ID, "runtime_observed_race", "RuntimeObservedRace", race.Execution, race.Artifact, string(payload)))
	}
	for _, access := range graph.Accesses {
		payload, _ := json.Marshal(access)
		item := runtimeEvidenceItem(access.ID, "runtime_access_observation", "RuntimeAccessObservation", access.Execution, RuntimeArtifactProvenance{ArtifactID: access.RawArtifactID, Digest: access.RawArtifactDigest, StorageRef: access.RawArtifactRef, ParserName: access.ParserName, ParserVersion: access.ParserVersion}, string(payload))
		item.AccessID = access.SourceAccessID
		out = append(out, item)
	}
	for _, overlap := range graph.Overlaps {
		payload, _ := json.Marshal(overlap)
		item := runtimeEvidenceItem(overlap.ID, "runtime_memory_location_overlap", "RuntimeMemoryLocationOverlap", overlap.Execution, overlap.Artifact, string(payload))
		item.Limitations = []string{"does not establish containing Go object, field identity, allocation identity, synchronization ordering, or happens-before"}
		out = append(out, item)
	}
	return out
}

func runtimeEvidenceItem(id, kind, claim string, execution ExecutionIdentity, artifact RuntimeArtifactProvenance, detail string) EvidenceItem {
	return EvidenceItem{ID: id, Kind: kind, ClaimKind: claim, Basis: "RuntimeObserved", RunID: execution.ExecutionID, ExecutionID: execution.ExecutionID, ReportID: execution.ReportID, BuildID: execution.BuildID, SourceRevision: execution.SourceRevision, TestAttemptID: execution.TestAttemptID, ArtifactID: artifact.ArtifactID, ArtifactDigest: artifact.Digest, StorageRef: artifact.StorageRef, ParserName: artifact.ParserName, ParserVersion: artifact.ParserVersion, Source: "Go race detector", Detail: detail, Provenance: artifact.StorageRef, Digest: artifact.Digest}
}

func RuntimeTraceEvidenceItem(trace ExecutionTraceObservation) EvidenceItem {
	payload, _ := json.Marshal(trace)
	return EvidenceItem{ID: "runtime-trace:" + trace.Execution.ExecutionID + ":" + trace.Execution.ReportID + ":" + trace.ArtifactDigest, Kind: "execution_trace_observation", ClaimKind: "ExecutionTraceObservation", Basis: "RuntimeObserved", RunID: trace.Execution.ExecutionID, ExecutionID: trace.Execution.ExecutionID, ReportID: trace.Execution.ReportID, BuildID: trace.Execution.BuildID, SourceRevision: trace.Execution.SourceRevision, TestAttemptID: trace.Execution.TestAttemptID, ArtifactID: trace.ArtifactRef, ArtifactDigest: trace.ArtifactDigest, StorageRef: trace.ArtifactRef, ParserName: "go-execution-trace-adapter", ParserVersion: trace.ParserVersion, TraceFormat: trace.TraceFormat, Source: "Go execution trace adapter", Detail: string(payload), Provenance: trace.ArtifactRef, Digest: trace.ArtifactDigest}
}

func RuntimeLifecycleEvidenceItems(events []GoroutineLifecycleObservation, trace ExecutionTraceObservation) []EvidenceItem {
	out := make([]EvidenceItem, 0, len(events))
	for _, event := range events {
		payload, _ := json.Marshal(event)
		out = append(out, EvidenceItem{ID: event.ID, Kind: "goroutine_lifecycle_observation", ClaimKind: "GoroutineLifecycleObservation", Basis: "RuntimeObserved", RunID: event.Execution.ExecutionID, ExecutionID: event.Execution.ExecutionID, ReportID: event.Execution.ReportID, BuildID: event.Execution.BuildID, SourceRevision: event.Execution.SourceRevision, TestAttemptID: event.Execution.TestAttemptID, ArtifactID: trace.ArtifactRef, ArtifactDigest: trace.ArtifactDigest, StorageRef: trace.ArtifactRef, ParserName: "go-execution-trace-adapter", ParserVersion: trace.ParserVersion, TraceFormat: trace.TraceFormat, Source: "Go execution trace adapter", Detail: string(payload), Provenance: trace.ArtifactRef, Digest: trace.ArtifactDigest})
	}
	return out
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func runtimeAccess(report RaceReport, op, address string, gid int64, stack, creation []localization.Frame, execution ExecutionIdentity, artifact RuntimeArtifactProvenance, index int) RuntimeAccessObservation {
	status := ClassifySourceResolution("", stack, false)
	return RuntimeAccessObservation{ID: fmt.Sprintf("runtime-access:%s:%s:%d:%s", execution.ExecutionID, execution.ReportID, index, op), Execution: execution, Operation: op, Address: address, GoroutineID: gid, Stack: append([]localization.Frame(nil), stack...), GoroutineCreationStack: append([]localization.Frame(nil), creation...), SourceResolutionStatus: status, SourceResolutionProvenance: "race_report_stack", RawArtifactRef: artifact.StorageRef, RawArtifactID: artifact.ArtifactID, RawArtifactDigest: artifact.Digest, ParserName: artifact.ParserName, ParserVersion: artifact.ParserVersion}
}

func creationStack(report RaceReport, goroutineID int64) []localization.Frame {
	if stack, ok := report.GoroutineCreationStacksByGoroutine[goroutineID]; ok {
		return stack
	}
	return nil
}

func raceEvidenceID(execution ExecutionIdentity, report RaceReport, index int) string {
	sum := sha256.Sum256([]byte(execution.ExecutionID + "\x00" + execution.ReportID + "\x00" + report.ReadAddress + "\x00" + report.WriteAddress + fmt.Sprint(index)))
	return "runtime-race:" + hex.EncodeToString(sum[:8])
}

func sameExecution(a, b ExecutionIdentity) bool {
	return a.ExecutionID != "" && b.ExecutionID != "" && a.ExecutionID == b.ExecutionID && a.BuildID != "" && a.BuildID == b.BuildID && a.SourceRevision != "" && a.SourceRevision == b.SourceRevision && a.TestAttemptID != "" && a.TestAttemptID == b.TestAttemptID
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
