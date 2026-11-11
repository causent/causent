package diagnosis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	pprofprofile "github.com/google/pprof/profile"
)

type ArtifactCategory string

const (
	ArtifactBuild       ArtifactCategory = "build_diagnostics"
	ArtifactTest        ArtifactCategory = "test_results"
	ArtifactRuntime     ArtifactCategory = "runtime_diagnostics"
	ArtifactTrace       ArtifactCategory = "execution_trace"
	ArtifactMemory      ArtifactCategory = "memory_diagnostics"
	ArtifactCoverage    ArtifactCategory = "coverage"
	ArtifactStatic      ArtifactCategory = "static_analysis"
	ArtifactInfra       ArtifactCategory = "infrastructure"
	ArtifactPerformance ArtifactCategory = "performance"
	ArtifactUnknown     ArtifactCategory = "unknown"
)

type ArtifactDecodeStatus string

const (
	ArtifactDecoded     ArtifactDecodeStatus = "decoded"
	ArtifactPartial     ArtifactDecodeStatus = "partial"
	ArtifactUnsupported ArtifactDecodeStatus = "unsupported"
	ArtifactMalformed   ArtifactDecodeStatus = "malformed"
)

type ArtifactDescriptor struct {
	ArtifactID     string           `json:"artifact_id,omitempty"`
	Provider       string           `json:"provider,omitempty"`
	WorkflowRunID  string           `json:"workflow_run_id,omitempty"`
	BuildID        string           `json:"build_id,omitempty"`
	ExecutionID    string           `json:"execution_id,omitempty"`
	TestAttemptID  string           `json:"test_attempt_id,omitempty"`
	SourceRevision string           `json:"source_revision,omitempty"`
	Name           string           `json:"name,omitempty"`
	Path           string           `json:"path,omitempty"`
	MediaType      string           `json:"media_type,omitempty"`
	Size           int64            `json:"size,omitempty"`
	Digest         string           `json:"digest,omitempty"`
	StorageRef     string           `json:"storage_ref,omitempty"`
	Category       ArtifactCategory `json:"category,omitempty"`
}

// ArtifactManifest is an optional provider-side identity map. Its entries
// refer to files below the artifact directory using relative paths. The
// manifest is metadata, not itself a diagnostic artifact.
type ArtifactManifest struct {
	Artifacts []ArtifactDescriptor `json:"artifacts"`
}

type ArtifactDetection struct {
	Format     string           `json:"format,omitempty"`
	Category   ArtifactCategory `json:"category"`
	Confidence string           `json:"confidence"`
	Reason     string           `json:"reason,omitempty"`
}

type ArtifactIngestionResult struct {
	Descriptor     ArtifactDescriptor   `json:"descriptor"`
	Detection      ArtifactDetection    `json:"detection"`
	Status         ArtifactDecodeStatus `json:"status"`
	DecoderName    string               `json:"decoder_name,omitempty"`
	DecoderVersion string               `json:"decoder_version,omitempty"`
	Evidence       []EvidenceItem       `json:"evidence,omitempty"`
	Limitations    []string             `json:"limitations,omitempty"`
}

type ArtifactDecoder interface {
	Name() string
	Version() string
	Detect(ArtifactDescriptor, []byte) ArtifactDetection
	Decode(ArtifactDescriptor, []byte, ArtifactDetection) ArtifactIngestionResult
}

type ArtifactDecoderRegistry struct {
	decoders []ArtifactDecoder
}

// DiscoverArtifactDescriptors enumerates artifacts without inspecting their
// format. Providers can implement the same discovery contract and hand these
// descriptors to the decoder registry. Unknown process identities remain
// empty in the supplied context.
func DiscoverArtifactDescriptors(root string, maxFiles int, context ArtifactDescriptor) ([]ArtifactDescriptor, []string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("artifact path is not a directory")
	}
	if maxFiles <= 0 {
		maxFiles = 20
	}
	var descriptors []ArtifactDescriptor
	var limitations []string
	manifest := map[string]ArtifactDescriptor{}
	manifestPath := filepath.Join(root, ".malenia-artifacts.json")
	if data, readErr := os.ReadFile(manifestPath); readErr == nil {
		var document ArtifactManifest
		if unmarshalErr := json.Unmarshal(data, &document); unmarshalErr != nil {
			limitations = append(limitations, fmt.Sprintf("%s: malformed artifact manifest: %v", manifestPath, unmarshalErr))
		} else {
			for _, entry := range document.Artifacts {
				key := filepath.ToSlash(filepath.Clean(entry.Path))
				if key != "." && key != "" {
					manifest[key] = entry
				}
			}
		}
	}
	filesSeen := 0
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !entry.Type().IsRegular() {
			return nil
		}
		if path == manifestPath {
			return nil
		}
		filesSeen++
		if len(descriptors) >= maxFiles {
			return nil
		}
		descriptor := context
		descriptor.Name = entry.Name()
		descriptor.Path = path
		descriptor.StorageRef = path
		relativePath, relativeErr := filepath.Rel(root, path)
		if relativeErr == nil {
			if entryMetadata, ok := manifest[filepath.ToSlash(filepath.Clean(relativePath))]; ok {
				descriptor.ArtifactID = entryMetadata.ArtifactID
				descriptor.Digest = entryMetadata.Digest
				if entryMetadata.StorageRef != "" {
					descriptor.StorageRef = entryMetadata.StorageRef
				}
			}
		}
		if stat, statErr := entry.Info(); statErr == nil {
			descriptor.Size = stat.Size()
		} else {
			limitations = append(limitations, fmt.Sprintf("%s: %v", path, statErr))
		}
		descriptors = append(descriptors, descriptor)
		return nil
	})
	if err != nil {
		return nil, limitations, err
	}
	if filesSeen > maxFiles {
		limitations = append(limitations, fmt.Sprintf("artifact file limit reached (%d); additional files were not discovered", maxFiles))
	}
	return descriptors, limitations, nil
}

func NewArtifactDecoderRegistry() *ArtifactDecoderRegistry {
	return &ArtifactDecoderRegistry{decoders: []ArtifactDecoder{
		junitArtifactDecoder{},
		nonJUnitTestReportArtifactDecoder{},
		raceArtifactDecoder{},
		runtimeExceptionArtifactDecoder{},
		sarifArtifactDecoder{},
		tapArtifactDecoder{},
		coverageArtifactDecoder{},
		structuredTraceArtifactDecoder{},
		openTelemetryArtifactDecoder{},
		nativeGoTraceArtifactDecoder{},
		coreDumpArtifactDecoder{},
		buildDiagnosticArtifactDecoder{},
		pprofArtifactDecoder{},
		containerLogArtifactDecoder{},
		flamegraphArtifactDecoder{},
		jsonArtifactDecoder{},
		textArtifactDecoder{},
	}}
}

// Register adds a decoder to the registry. Decoders registered later are
// considered after the built-in, higher-confidence decoders.
func (r *ArtifactDecoderRegistry) Register(decoder ArtifactDecoder) {
	if decoder != nil {
		r.decoders = append(r.decoders, decoder)
	}
}

func (r *ArtifactDecoderRegistry) Ingest(desc ArtifactDescriptor, data []byte) ArtifactIngestionResult {
	if desc.Digest == "" {
		sum := sha256.Sum256(data)
		desc.Digest = hex.EncodeToString(sum[:])
	}
	if desc.Size == 0 {
		desc.Size = int64(len(data))
	}
	for _, decoder := range r.decoders {
		detection := decoder.Detect(desc, data)
		if detection.Confidence == "none" {
			continue
		}
		result := decoder.Decode(desc, data, detection)
		result.Descriptor = desc
		result.Detection = detection
		result.DecoderName = decoder.Name()
		result.DecoderVersion = decoder.Version()
		for i := range result.Evidence {
			result.Evidence[i] = decorateArtifactEvidence(result.Evidence[i], desc, detection, decoder)
			result.Evidence[i].DecoderStatus = string(result.Status)
		}
		return result
	}
	return ArtifactIngestionResult{Descriptor: desc, Detection: ArtifactDetection{Category: ArtifactUnknown, Confidence: "none", Reason: "no registered decoder recognized the artifact"}, Status: ArtifactUnsupported, Limitations: []string{"artifact format was not recognized"}}
}

func decorateArtifactEvidence(item EvidenceItem, desc ArtifactDescriptor, detection ArtifactDetection, decoder ArtifactDecoder) EvidenceItem {
	if item.ArtifactID == "" {
		item.ArtifactID = desc.ArtifactID
	}
	if item.ArtifactDigest == "" {
		item.ArtifactDigest = desc.Digest
	}
	if item.StorageRef == "" {
		item.StorageRef = desc.StorageRef
	}
	if item.Provenance == "" {
		item.Provenance = desc.StorageRef
	}
	item.ArtifactCategory = string(detection.Category)
	item.ArtifactFormat = detection.Format
	item.WorkflowRunID = desc.WorkflowRunID
	item.BuildID = desc.BuildID
	item.SourceRevision = desc.SourceRevision
	item.DecoderStatus = string(ArtifactDecoded)
	item.ParserName = decoder.Name()
	item.ParserVersion = decoder.Version()
	return item
}

func LoadArtifactEvidence(root string, maxFiles int, maxBytes int64) ([]EvidenceItem, error) {
	return LoadArtifactEvidenceWithContext(root, maxFiles, maxBytes, ArtifactDescriptor{})
}

// LoadArtifactEvidenceWithContext is the provider-neutral file loader. The
// context contains identities already established by the CI adapter; empty
// identities remain empty and are never derived from filenames or digests.
func LoadArtifactEvidenceWithContext(root string, maxFiles int, maxBytes int64, context ArtifactDescriptor) ([]EvidenceItem, error) {
	if maxFiles <= 0 {
		maxFiles = 20
	}
	if maxBytes <= 0 {
		maxBytes = 256 << 10
	}
	registry := NewArtifactDecoderRegistry()
	var evidence []EvidenceItem
	descriptors, limitations, err := DiscoverArtifactDescriptors(root, maxFiles, context)
	if err != nil {
		return nil, err
	}
	for _, descriptor := range descriptors {
		path := descriptor.Path
		data, readErr := readArtifactBytes(path, maxBytes)
		if readErr != nil {
			limitations = append(limitations, fmt.Sprintf("%s: %v", path, readErr))
			continue
		}
		rawSum := sha256.Sum256(data)
		redacted := redactArtifact(data)
		redactedSum := sha256.Sum256(redacted)
		artifactID := descriptor.ArtifactID
		manifestIdentity := artifactID != ""
		if artifactID == "" {
			artifactID = "artifact:" + hex.EncodeToString(rawSum[:8])
		}
		desc := descriptor
		desc.ArtifactID = artifactID
		if desc.Digest == "" {
			desc.Digest = hex.EncodeToString(rawSum[:])
		}
		desc.Size = int64(len(data))
		result := registry.Ingest(desc, redacted)
		if len(result.Evidence) == 0 {
			result.Evidence = []EvidenceItem{{ID: "E-" + artifactID, Kind: "ci_artifact", Source: path, Detail: string(redacted), Digest: hex.EncodeToString(redactedSum[:]), Provenance: desc.StorageRef, ArtifactCategory: string(result.Detection.Category), ArtifactFormat: result.Detection.Format, DecoderStatus: string(result.Status), ParserName: result.DecoderName, ParserVersion: result.DecoderVersion, Limitations: result.Limitations}}
		}
		for i := range result.Evidence {
			if manifestIdentity {
				result.Evidence[i].ID = fmt.Sprintf("E-%s-%s-%d", artifactID, hex.EncodeToString(rawSum[:4]), i)
			}
			result.Evidence[i].Source = path
			result.Evidence[i].ArtifactID = artifactID
			result.Evidence[i].ArtifactDigest = desc.Digest
			result.Evidence[i].StorageRef = desc.StorageRef
			result.Evidence[i].Digest = hex.EncodeToString(redactedSum[:])
		}
		evidence = append(evidence, result.Evidence...)
	}
	if len(limitations) > 0 {
		evidence = append(evidence, EvidenceItem{ID: fmt.Sprintf("E-artifact-limitations-%d", len(evidence)+1), Kind: "ci_artifact_manifest", Source: root, Detail: strings.Join(limitations, "\n"), Provenance: root, Limitations: limitations, ArtifactCategory: string(ArtifactUnknown), DecoderStatus: string(ArtifactPartial)})
	}
	return evidence, err
}

func readArtifactBytes(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return data[:limit], fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	return data, nil
}

var artifactSecret = regexp.MustCompile(`(?i)((?:authorization|token|password|secret|api[_-]?key)[=:][[:space:]]*)(?:"[^"]*"|'[^']*'|[^[:space:]\r\n"'<>]+)`)

func redactArtifact(data []byte) []byte {
	return artifactSecret.ReplaceAll(data, []byte(`${1}[REDACTED]`))
}

type junitArtifactDecoder struct{}

func (junitArtifactDecoder) Name() string    { return "junit" }
func (junitArtifactDecoder) Version() string { return "v1" }
func (junitArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	if strings.Contains(strings.ToLower(desc.Name), "junit") || strings.Contains(strings.ToLower(desc.Name), "test-result") || strings.HasPrefix(strings.TrimSpace(string(data)), "<testsuite") || strings.HasPrefix(strings.TrimSpace(string(data)), "<testsuites") {
		return ArtifactDetection{Format: "junit_xml", Category: ArtifactTest, Confidence: "high", Reason: "JUnit root element or artifact name"}
	}
	return ArtifactDetection{Confidence: "none"}
}
func (junitArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	if _, err := ParseJUnitXML(string(data), EvidenceProvenance{URI: desc.StorageRef}); err != nil {
		return ArtifactIngestionResult{Status: ArtifactMalformed, Limitations: []string{err.Error()}}
	}
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "junit_report", ClaimKind: "test_result", Basis: "Observed", Detail: string(data), Provenance: desc.StorageRef}}}
}

type nonJUnitTestReportArtifactDecoder struct{}

func (nonJUnitTestReportArtifactDecoder) Name() string    { return "xml-test-report" }
func (nonJUnitTestReportArtifactDecoder) Version() string { return "v1" }
func (nonJUnitTestReportArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	text := strings.TrimSpace(string(data))
	for _, root := range []string{"<test-run", "<test-results", "<testResults", "<assemblies", "<test-runner"} {
		if strings.Contains(text, root) {
			return ArtifactDetection{Format: "xml_test_report", Category: ArtifactTest, Confidence: "high", Reason: "non-JUnit test runner XML root"}
		}
	}
	return ArtifactDetection{Confidence: "none"}
}
func (nonJUnitTestReportArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	var document struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(data, &document); err != nil {
		return ArtifactIngestionResult{Status: ArtifactMalformed, Limitations: []string{err.Error()}}
	}
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "test_report", ClaimKind: "test_result", Basis: "Observed", Detail: string(data), Provenance: desc.StorageRef}}}
}

type raceArtifactDecoder struct{}

func (raceArtifactDecoder) Name() string    { return "go-race-report" }
func (raceArtifactDecoder) Version() string { return "v1" }
func (raceArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	if strings.Contains(string(data), "WARNING: DATA RACE") {
		return ArtifactDetection{Format: "go_race_report", Category: ArtifactRuntime, Confidence: "high", Reason: "Go race detector marker"}
	}
	return ArtifactDetection{Confidence: "none"}
}
func (raceArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	if len(parseRaceReports(string(data))) == 0 {
		return ArtifactIngestionResult{Status: ArtifactMalformed, Limitations: []string{"race marker found but no race report was parsed"}}
	}
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "ci_artifact", ClaimKind: "RuntimeObservedRace", Basis: "RuntimeObserved", Detail: string(data), Provenance: desc.StorageRef}}}
}

type sarifArtifactDecoder struct{}

func (sarifArtifactDecoder) Name() string    { return "sarif" }
func (sarifArtifactDecoder) Version() string { return "v1" }
func (sarifArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if json.Unmarshal(data, &doc) != nil || len(doc.Runs) == 0 || doc.Version == "" || doc.Runs[0].Tool.Driver.Name == "" {
		return ArtifactDetection{Confidence: "none"}
	}
	return ArtifactDetection{Format: "sarif", Category: ArtifactStatic, Confidence: "high", Reason: "SARIF version and tool driver fields"}
}
func (sarifArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return ArtifactIngestionResult{Status: ArtifactMalformed, Limitations: []string{err.Error()}}
	}
	count := 0
	for _, run := range doc.Runs {
		count += len(run.Results)
	}
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "static_analysis_report", ClaimKind: "static_analysis", Basis: "Observed", Detail: fmt.Sprintf("SARIF report with %d result(s): %s", count, string(data)), Provenance: desc.StorageRef}}}
}

type tapArtifactDecoder struct{}

func (tapArtifactDecoder) Name() string    { return "tap" }
func (tapArtifactDecoder) Version() string { return "v1" }
func (tapArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	text := string(data)
	if !strings.Contains(text, "TAP version") && !regexp.MustCompile(`(?m)^\s*(?:not )?ok\b`).MatchString(text) {
		return ArtifactDetection{Confidence: "none"}
	}
	return ArtifactDetection{Format: "tap", Category: ArtifactTest, Confidence: "high", Reason: "TAP version or test result lines"}
}
func (tapArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	resultLine := regexp.MustCompile(`(?m)^\s*(not )?ok\b(?:\s+\d+)?(?:\s+-\s+)?([^\r\n]*)`)
	matches := resultLine.FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		return ArtifactIngestionResult{Status: ArtifactMalformed, Limitations: []string{"TAP marker found but no test result lines were parsed"}}
	}
	failed := 0
	for _, match := range matches {
		if match[1] != "" {
			failed++
		}
	}
	detail := fmt.Sprintf("TAP report with %d test result(s), %d failure(s): %s", len(matches), failed, string(data))
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "tap_report", ClaimKind: "test_result", Basis: "Observed", Detail: detail, Provenance: desc.StorageRef}}}
}

type coverageArtifactDecoder struct{}

func (coverageArtifactDecoder) Name() string    { return "coverage" }
func (coverageArtifactDecoder) Version() string { return "v1" }
func (coverageArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	text := strings.TrimSpace(string(data))
	switch {
	case strings.Contains(text, "SF:") && strings.Contains(text, "DA:"):
		return ArtifactDetection{Format: "lcov", Category: ArtifactCoverage, Confidence: "high", Reason: "LCOV source and line records"}
	case strings.HasPrefix(text, "<?xml") && strings.Contains(text, "<coverage"):
		return ArtifactDetection{Format: "cobertura_xml", Category: ArtifactCoverage, Confidence: "high", Reason: "Cobertura coverage root"}
	case strings.HasPrefix(text, "<?xml") && strings.Contains(text, "<report"):
		return ArtifactDetection{Format: "jacoco_xml", Category: ArtifactCoverage, Confidence: "medium", Reason: "JaCoCo report root"}
	default:
		return ArtifactDetection{Confidence: "none"}
	}
}
func (coverageArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	if detection.Format != "lcov" {
		var document struct {
			XMLName xml.Name
		}
		if err := xml.Unmarshal(data, &document); err != nil {
			return ArtifactIngestionResult{Status: ArtifactMalformed, Limitations: []string{err.Error()}}
		}
	}
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "coverage_report", ClaimKind: "coverage_observation", Basis: "Observed", Detail: string(data), Provenance: desc.StorageRef}}}
}

type runtimeExceptionArtifactDecoder struct{}

func (runtimeExceptionArtifactDecoder) Name() string    { return "runtime-exception" }
func (runtimeExceptionArtifactDecoder) Version() string { return "v1" }
func (runtimeExceptionArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	text := string(data)
	switch {
	case strings.Contains(text, "Traceback (most recent call last):"), strings.Contains(text, "panic:"), strings.Contains(text, "Exception in thread "), regexp.MustCompile(`(?m)^\s*[A-Za-z0-9_$.]+(?:Error|Exception|Failure):\s*`).MatchString(text):
		return ArtifactDetection{Format: "runtime_exception_text", Category: ArtifactRuntime, Confidence: "medium", Reason: "language runtime exception or panic marker"}
	default:
		return ArtifactDetection{Confidence: "none"}
	}
}

func (runtimeExceptionArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "runtime_exception_report", ClaimKind: "RuntimeExceptionObservation", Basis: "RuntimeObserved", Detail: string(data), Provenance: desc.StorageRef}}}
}

type structuredTraceArtifactDecoder struct{}

func (structuredTraceArtifactDecoder) Name() string    { return "structured-execution-trace" }
func (structuredTraceArtifactDecoder) Version() string { return "v1" }
func (structuredTraceArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	var document JSONTraceDocument
	if json.Unmarshal(data, &document) != nil || document.FormatVersion == "" || len(document.Events) == 0 {
		return ArtifactDetection{Confidence: "none"}
	}
	return ArtifactDetection{Format: document.FormatVersion, Category: ArtifactTrace, Confidence: "high", Reason: "structured lifecycle trace format and events"}
}
func (structuredTraceArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	meta := ExecutionTraceObservation{
		Execution: ExecutionIdentity{
			WorkflowRunID:  desc.WorkflowRunID,
			ReportID:       desc.ArtifactID,
			BuildID:        desc.BuildID,
			SourceRevision: desc.SourceRevision,
			TestAttemptID:  desc.TestAttemptID,
		},
		TraceFormat:    detection.Format,
		ArtifactDigest: desc.Digest,
		ArtifactRef:    desc.StorageRef,
		ParserVersion:  "v1",
	}
	parsedMeta, lifecycle, err := ParseStructuredTraceObservation(data, meta)
	if err != nil {
		return ArtifactIngestionResult{Status: ArtifactMalformed, Limitations: []string{err.Error()}}
	}
	evidence := []EvidenceItem{RuntimeTraceEvidenceItem(parsedMeta)}
	evidence = append(evidence, RuntimeLifecycleEvidenceItems(lifecycle, parsedMeta)...)
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: evidence}
}

type openTelemetryArtifactDecoder struct{}

func (openTelemetryArtifactDecoder) Name() string    { return "opentelemetry-json" }
func (openTelemetryArtifactDecoder) Version() string { return "v1" }
func (openTelemetryArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	var document struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []json.RawMessage `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if json.Unmarshal(data, &document) != nil || len(document.ResourceSpans) == 0 {
		return ArtifactDetection{Confidence: "none"}
	}
	for _, resource := range document.ResourceSpans {
		for _, scope := range resource.ScopeSpans {
			if len(scope.Spans) > 0 {
				return ArtifactDetection{Format: "opentelemetry_json", Category: ArtifactTrace, Confidence: "high", Reason: "OTLP resourceSpans and span records"}
			}
		}
	}
	return ArtifactDetection{Confidence: "none"}
}
func (openTelemetryArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	var document struct {
		ResourceSpans []struct {
			ScopeSpans []struct {
				Spans []json.RawMessage `json:"spans"`
			} `json:"scopeSpans"`
		} `json:"resourceSpans"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return ArtifactIngestionResult{Status: ArtifactMalformed, Limitations: []string{err.Error()}}
	}
	spanCount := 0
	for _, resource := range document.ResourceSpans {
		for _, scope := range resource.ScopeSpans {
			spanCount += len(scope.Spans)
		}
	}
	if spanCount == 0 {
		return ArtifactIngestionResult{Status: ArtifactMalformed, Limitations: []string{"OTLP document contained no spans"}}
	}
	meta := ExecutionTraceObservation{Execution: ExecutionIdentity{WorkflowRunID: desc.WorkflowRunID, ReportID: desc.ArtifactID, BuildID: desc.BuildID, SourceRevision: desc.SourceRevision, TestAttemptID: desc.TestAttemptID}, TraceFormat: detection.Format, ArtifactDigest: desc.Digest, ArtifactRef: desc.StorageRef, ParserVersion: "v1"}
	payload, _ := json.Marshal(struct {
		Observation ExecutionTraceObservation `json:"observation"`
		SpanCount   int                       `json:"span_count"`
		Raw         string                    `json:"raw"`
	}{Observation: meta, SpanCount: spanCount, Raw: string(data)})
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "execution_trace_observation", ClaimKind: "ExecutionTraceObservation", Basis: "RuntimeObserved", Detail: string(payload), Provenance: desc.StorageRef}}}
}

type nativeGoTraceArtifactDecoder struct{}

func (nativeGoTraceArtifactDecoder) Name() string    { return "go-runtime-trace" }
func (nativeGoTraceArtifactDecoder) Version() string { return "detector-v1" }
func (nativeGoTraceArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) >= 5 && bytes.HasPrefix(trimmed, []byte("go 1.")) && bytes.Contains(trimmed[:min(len(trimmed), 64)], []byte("trace")) {
		return ArtifactDetection{Format: "go_runtime_trace_binary", Category: ArtifactTrace, Confidence: "high", Reason: "Go runtime trace header detected"}
	}
	return ArtifactDetection{Confidence: "none"}
}
func (nativeGoTraceArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	return ArtifactIngestionResult{Status: ArtifactUnsupported, Limitations: []string{"native Go execution trace binary detected; version-aware binary parser is not available, so no lifecycle or causal observations were produced"}, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "execution_trace_artifact", ClaimKind: "ExecutionTraceArtifact", Basis: "Observed", Detail: "Native Go execution trace artifact preserved without parsing", Provenance: desc.StorageRef}}}
}

type coreDumpArtifactDecoder struct{}

func (coreDumpArtifactDecoder) Name() string    { return "core-dump-detector" }
func (coreDumpArtifactDecoder) Version() string { return "detector-v1" }
func (coreDumpArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	if len(data) >= 20 && bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		// ELF e_type is at byte 16. ET_CORE is 4 for both 32- and 64-bit ELF.
		littleEndian := data[5] == 1
		var objectType uint16
		if littleEndian {
			objectType = uint16(data[16]) | uint16(data[17])<<8
		} else {
			objectType = uint16(data[16])<<8 | uint16(data[17])
		}
		if objectType == 4 {
			return ArtifactDetection{Format: "elf_core_dump", Category: ArtifactMemory, Confidence: "high", Reason: "ELF ET_CORE header"}
		}
	}
	if len(data) >= 4 && bytes.Equal(data[:4], []byte("MDMP")) {
		return ArtifactDetection{Format: "minidump", Category: ArtifactMemory, Confidence: "high", Reason: "minidump signature"}
	}
	return ArtifactDetection{Confidence: "none"}
}
func (coreDumpArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	return ArtifactIngestionResult{Status: ArtifactUnsupported, Limitations: []string{"memory dump detected; debugger- and platform-specific dump parser is not available, so no process-state or object-identity claims were produced"}, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "memory_dump_artifact", ClaimKind: "MemoryDiagnosticArtifact", Basis: "Observed", Detail: "Memory diagnostic artifact preserved without parsing", Provenance: desc.StorageRef}}}
}

type buildDiagnosticArtifactDecoder struct{}

var buildDiagnosticLine = regexp.MustCompile(`(?m)^(?:[^\r\n:]+:)?[^\r\n]*:[0-9]+(?::[0-9]+)?:\s*(?:fatal\s+)?(?:error\b|undefined:|cannot find|undeclared|no required module)|^error(?:\[[^\r\n\]]+\])?:\s+`)

func (buildDiagnosticArtifactDecoder) Name() string    { return "compiler-diagnostic" }
func (buildDiagnosticArtifactDecoder) Version() string { return "v1" }
func (buildDiagnosticArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	if len(buildDiagnosticLine.FindAllString(string(data), -1)) > 0 {
		return ArtifactDetection{Format: "compiler_diagnostics", Category: ArtifactBuild, Confidence: "high", Reason: "compiler diagnostic error locations"}
	}
	return ArtifactDetection{Confidence: "none"}
}
func (buildDiagnosticArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	count := len(buildDiagnosticLine.FindAllString(string(data), -1))
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "build_diagnostic", ClaimKind: "BuildDiagnosticObservation", Basis: "Observed", Detail: fmt.Sprintf("compiler/build report with %d diagnostic error(s): %s", count, string(data)), Provenance: desc.StorageRef}}}
}

type pprofArtifactDecoder struct{}

func (pprofArtifactDecoder) Name() string    { return "pprof-profile" }
func (pprofArtifactDecoder) Version() string { return "v1" }
func (pprofArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	lowerName := strings.ToLower(desc.Name)
	nameHint := strings.Contains(lowerName, "pprof") || strings.Contains(lowerName, "profile") || strings.Contains(lowerName, "heap") || strings.Contains(lowerName, "cpu")
	binaryHint := (len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b) || bytes.IndexByte(data, 0) >= 0
	if nameHint && binaryHint {
		return ArtifactDetection{Format: "pprof", Category: ArtifactPerformance, Confidence: "high", Reason: "profile artifact name and binary/gzip profile payload"}
	}
	return ArtifactDetection{Confidence: "none"}
}
func (pprofArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	parsed, err := pprofprofile.ParseData(data)
	if err != nil {
		return ArtifactIngestionResult{Status: ArtifactMalformed, Limitations: []string{err.Error()}}
	}
	sampleTypes := make([]string, 0, len(parsed.SampleType))
	for _, sampleType := range parsed.SampleType {
		if sampleType != nil {
			sampleTypes = append(sampleTypes, sampleType.Type+"/"+sampleType.Unit)
		}
	}
	detail := fmt.Sprintf("pprof profile with %d sample(s), %d function(s), types=%s, duration_nanos=%d", len(parsed.Sample), len(parsed.Function), strings.Join(sampleTypes, ","), parsed.DurationNanos)
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "performance_profile", ClaimKind: "PerformanceProfileObservation", Basis: "Observed", Detail: detail, Provenance: desc.StorageRef}}}
}

type containerLogArtifactDecoder struct{}

func (containerLogArtifactDecoder) Name() string    { return "container-json-log" }
func (containerLogArtifactDecoder) Version() string { return "v1" }
func (containerLogArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	if count := containerLogEntryCount(data); count > 0 {
		return ArtifactDetection{Format: "container_json_log", Category: ArtifactInfra, Confidence: "high", Reason: "container log records with timestamp, stream, and log fields"}
	}
	return ArtifactDetection{Confidence: "none"}
}
func (containerLogArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	count := containerLogEntryCount(data)
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "container_log_observation", ClaimKind: "InfrastructureLogObservation", Basis: "Observed", Detail: fmt.Sprintf("container log with %d record(s): %s", count, string(data)), Provenance: desc.StorageRef}}}
}

func containerLogEntryCount(data []byte) int {
	type record struct {
		Time   string `json:"time"`
		Stream string `json:"stream"`
		Log    string `json:"log"`
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		var entry record
		if json.Unmarshal([]byte(line), &entry) == nil && entry.Time != "" && entry.Stream != "" && entry.Log != "" {
			count++
		}
	}
	return count
}

type flamegraphArtifactDecoder struct{}

var collapsedStackLine = regexp.MustCompile(`(?m)^[^\r\n;]+(?:;[^\r\n;]+)+\s+[0-9]+(?:\.[0-9]+)?\s*$`)

func (flamegraphArtifactDecoder) Name() string    { return "collapsed-stack" }
func (flamegraphArtifactDecoder) Version() string { return "v1" }
func (flamegraphArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	if matches := collapsedStackLine.FindAllString(string(data), -1); len(matches) > 0 {
		return ArtifactDetection{Format: "collapsed_stacks", Category: ArtifactPerformance, Confidence: "high", Reason: "collapsed stack paths with sample counts"}
	}
	return ArtifactDetection{Confidence: "none"}
}
func (flamegraphArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	count := len(collapsedStackLine.FindAllString(string(data), -1))
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "performance_profile", ClaimKind: "PerformanceProfileObservation", Basis: "Observed", Detail: fmt.Sprintf("collapsed stack profile with %d sample path(s): %s", count, string(data)), Provenance: desc.StorageRef}}}
}

type jsonArtifactDecoder struct{}

func (jsonArtifactDecoder) Name() string    { return "structured-json" }
func (jsonArtifactDecoder) Version() string { return "v1" }
func (jsonArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	if !json.Valid(data) {
		return ArtifactDetection{Confidence: "none"}
	}
	return ArtifactDetection{Format: "json", Category: ArtifactUnknown, Confidence: "low", Reason: "valid JSON artifact; schema-specific decoder unavailable"}
}
func (jsonArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	return ArtifactIngestionResult{Status: ArtifactUnsupported, Limitations: []string{"JSON schema was not recognized; raw artifact preserved"}, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "ci_artifact", Detail: string(data), Provenance: desc.StorageRef}}}
}

type textArtifactDecoder struct{}

func (textArtifactDecoder) Name() string    { return "ci-text" }
func (textArtifactDecoder) Version() string { return "v1" }
func (textArtifactDecoder) Detect(desc ArtifactDescriptor, data []byte) ArtifactDetection {
	if strings.IndexByte(string(data), 0) >= 0 {
		return ArtifactDetection{Confidence: "none"}
	}
	return ArtifactDetection{Format: "text", Category: ArtifactBuild, Confidence: "low", Reason: "text artifact fallback"}
}
func (textArtifactDecoder) Decode(desc ArtifactDescriptor, data []byte, detection ArtifactDetection) ArtifactIngestionResult {
	return ArtifactIngestionResult{Status: ArtifactDecoded, Evidence: []EvidenceItem{{ID: "E-" + desc.ArtifactID, Kind: "ci_artifact", Detail: string(data), Provenance: desc.StorageRef}}}
}
