package diagnosis

import (
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

func NewArtifactDecoderRegistry() *ArtifactDecoderRegistry {
	return &ArtifactDecoderRegistry{decoders: []ArtifactDecoder{
		junitArtifactDecoder{},
		raceArtifactDecoder{},
		sarifArtifactDecoder{},
		tapArtifactDecoder{},
		coverageArtifactDecoder{},
		structuredTraceArtifactDecoder{},
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
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("artifact path is not a directory")
	}
	if maxFiles <= 0 {
		maxFiles = 20
	}
	if maxBytes <= 0 {
		maxBytes = 256 << 10
	}
	registry := NewArtifactDecoderRegistry()
	var evidence []EvidenceItem
	var limitations []string
	filesSeen := 0
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filesSeen >= maxFiles || entry.IsDir() || !entry.Type().IsRegular() {
			if filesSeen >= maxFiles {
				return filepath.SkipDir
			}
			return nil
		}
		data, readErr := readArtifactBytes(path, maxBytes)
		if readErr != nil {
			limitations = append(limitations, fmt.Sprintf("%s: %v", path, readErr))
			return nil
		}
		filesSeen++
		rawSum := sha256.Sum256(data)
		redacted := redactArtifact(data)
		redactedSum := sha256.Sum256(redacted)
		artifactID := "artifact:" + hex.EncodeToString(rawSum[:8])
		desc := context
		desc.ArtifactID = artifactID
		desc.Name = entry.Name()
		desc.Path = path
		desc.StorageRef = path
		desc.Digest = hex.EncodeToString(rawSum[:])
		desc.Size = int64(len(data))
		result := registry.Ingest(desc, redacted)
		if len(result.Evidence) == 0 {
			result.Evidence = []EvidenceItem{{ID: "E-" + artifactID, Kind: "ci_artifact", Source: path, Detail: string(redacted), Digest: hex.EncodeToString(redactedSum[:]), Provenance: path, ArtifactCategory: string(result.Detection.Category), ArtifactFormat: result.Detection.Format, DecoderStatus: string(result.Status), ParserName: result.DecoderName, ParserVersion: result.DecoderVersion, Limitations: result.Limitations}}
		}
		for i := range result.Evidence {
			result.Evidence[i].Source = path
			result.Evidence[i].ArtifactID = artifactID
			result.Evidence[i].ArtifactDigest = desc.Digest
			result.Evidence[i].StorageRef = path
			result.Evidence[i].Digest = hex.EncodeToString(redactedSum[:])
		}
		evidence = append(evidence, result.Evidence...)
		return nil
	})
	if filesSeen >= maxFiles {
		limitations = append(limitations, fmt.Sprintf("artifact file limit reached (%d); additional files were not ingested", maxFiles))
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
