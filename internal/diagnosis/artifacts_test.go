package diagnosis

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/causent/malenia/internal/domain"
)

func TestArtifactRegistryDetectsByContentAndPreservesRawProvenance(t *testing.T) {
	root := t.TempDir()
	content := []byte(`<testsuites><testsuite name="unit"><testcase name="ok"/></testsuite></testsuites>`)
	path := filepath.Join(root, "opaque.bin")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}

	items, err := LoadArtifactEvidence(root, 10, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1: %#v", len(items), items)
	}
	item := items[0]
	wantDigest := sha256.Sum256(content)
	if item.ArtifactDigest != hex.EncodeToString(wantDigest[:]) || item.ArtifactID == "" || item.StorageRef != path {
		t.Fatalf("raw provenance not preserved: %#v", item)
	}
	if item.ArtifactFormat != "junit_xml" || item.ArtifactCategory != string(ArtifactTest) || item.DecoderStatus != string(ArtifactDecoded) || item.ParserName != "junit" || item.ParserVersion != "v1" {
		t.Fatalf("content decoder metadata missing: %#v", item)
	}
}

func TestArtifactLoadPreservesEstablishedCIContextWithoutSynthesizingExecution(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "failure.log")
	if err := os.WriteFile(path, []byte("build failed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	items, err := LoadArtifactEvidenceWithContext(root, 10, 1024, ArtifactDescriptor{
		Provider:       "github-actions",
		WorkflowRunID:  "run-42",
		BuildID:        "build-7",
		SourceRevision: "abc123",
	})
	if err != nil || len(items) != 1 {
		t.Fatalf("items = %#v, err = %v", items, err)
	}
	item := items[0]
	if item.ExecutionID != "" || item.ReportID != "" || item.WorkflowRunID != "run-42" || item.BuildID != "build-7" || item.SourceRevision != "abc123" {
		t.Fatalf("identity was synthesized or lost: %#v", item)
	}
}

func TestArtifactDiscoveryDoesNotDecodeContent(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "report.xml")
	if err := os.WriteFile(path, []byte(`<testsuite/>`), 0600); err != nil {
		t.Fatal(err)
	}
	descriptors, limitations, err := DiscoverArtifactDescriptors(root, 10, ArtifactDescriptor{Provider: "fixture"})
	if err != nil || len(limitations) != 0 || len(descriptors) != 1 {
		t.Fatalf("discovery = %#v, limitations = %#v, err = %v", descriptors, limitations, err)
	}
	if descriptors[0].Name != "report.xml" || descriptors[0].Path != path || descriptors[0].Provider != "fixture" || descriptors[0].Digest != "" || descriptors[0].Category != "" {
		t.Fatalf("discovery decoded or synthesized format data: %#v", descriptors[0])
	}
}

func TestArtifactIngestionStatusesAndIdempotency(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"bad-junit.xml": "<testsuites>",
		"unknown.json":  `{"kind":"unknown"}`,
		"plain.log":     "build failed at compiler.go:12\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	first, err := LoadArtifactEvidence(root, 10, 1024)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadArtifactEvidence(root, 10, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(second) {
		t.Fatalf("repeat ingestion changed result count: %d vs %d", len(first), len(second))
	}
	bySource := func(items []EvidenceItem) map[string]EvidenceItem {
		out := make(map[string]EvidenceItem)
		for _, item := range items {
			out[item.Source] = item
		}
		return out
	}
	a, b := bySource(first), bySource(second)
	for source, item := range a {
		other, ok := b[source]
		if !ok || item.ID != other.ID || item.ArtifactID != other.ArtifactID || item.ArtifactDigest != other.ArtifactDigest {
			t.Fatalf("repeat ingestion was not stable for %s: %#v vs %#v", source, item, other)
		}
	}
	if a[filepath.Join(root, "bad-junit.xml")].DecoderStatus != string(ArtifactMalformed) {
		t.Fatalf("malformed artifact status = %q", a[filepath.Join(root, "bad-junit.xml")].DecoderStatus)
	}
	if a[filepath.Join(root, "unknown.json")].DecoderStatus != string(ArtifactUnsupported) {
		t.Fatalf("unsupported artifact status = %q", a[filepath.Join(root, "unknown.json")].DecoderStatus)
	}
	if a[filepath.Join(root, "plain.log")].DecoderStatus != string(ArtifactDecoded) {
		t.Fatalf("text artifact status = %q", a[filepath.Join(root, "plain.log")].DecoderStatus)
	}
}

func TestArtifactIngestionPreservesLimitations(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "large.log"), []byte("0123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	items, err := LoadArtifactEvidence(root, 10, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].DecoderStatus != string(ArtifactPartial) || len(items[0].Limitations) == 0 {
		t.Fatalf("bounded artifact limitation missing: %#v", items)
	}
}

func TestArtifactRegistryDecodesGenericFormats(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		format string
		kind   string
		cat    ArtifactCategory
	}{
		{name: "sarif", data: `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"lint"}},"results":[{"ruleId":"R1","message":{"text":"bad"}}]}]}`, format: "sarif", kind: "static_analysis_report", cat: ArtifactStatic},
		{name: "tap", data: "TAP version 13\n1..1\nok 1 - works\n", format: "tap", kind: "tap_report", cat: ArtifactTest},
		{name: "lcov", data: "TN:\nSF:pkg/main.go\nDA:1,1\nend_of_record\n", format: "lcov", kind: "coverage_report", cat: ArtifactCoverage},
		{name: "cobertura", data: `<?xml version="1.0"?><coverage><packages/></coverage>`, format: "cobertura_xml", kind: "coverage_report", cat: ArtifactCoverage},
		{name: "jacoco", data: `<?xml version="1.0"?><report name="unit"><package name="pkg"/></report>`, format: "jacoco_xml", kind: "coverage_report", cat: ArtifactCoverage},
		{name: "trace", data: `{"format_version":"structured-trace-v1","events":[{"goroutine_id":7,"kind":"created","timestamp":10}]}`, format: "structured-trace-v1", kind: "execution_trace_observation", cat: ArtifactTrace},
		{name: "otlp", data: `{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"request","traceId":"abc"}]}]}]}`, format: "opentelemetry_json", kind: "execution_trace_observation", cat: ArtifactTrace},
		{name: "python-exception", data: "Traceback (most recent call last):\n  File \"app.py\", line 4\nValueError: bad input\n", format: "runtime_exception_text", kind: "runtime_exception_report", cat: ArtifactRuntime},
	}
	registry := NewArtifactDecoderRegistry()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := registry.Ingest(ArtifactDescriptor{ArtifactID: "artifact:" + tc.name, StorageRef: "artifact://" + tc.name, Name: tc.name}, []byte(tc.data))
			if result.Status != ArtifactDecoded || len(result.Evidence) == 0 {
				t.Fatalf("result = %#v", result)
			}
			item := result.Evidence[0]
			if item.Kind != tc.kind || item.ArtifactFormat != tc.format || item.ArtifactCategory != string(tc.cat) || item.DecoderStatus != string(ArtifactDecoded) {
				t.Fatalf("normalized evidence = %#v", item)
			}
			if tc.name == "trace" && len(result.Evidence) != 2 {
				t.Fatalf("trace evidence count = %d, want trace plus lifecycle", len(result.Evidence))
			}
			if tc.name == "trace" {
				for _, evidence := range result.Evidence {
					if evidence.ClaimKind == "HappensBefore" || evidence.ClaimKind == "RuntimeObjectIdentity" || evidence.Ordering != "" {
						t.Fatalf("trace decoder produced causal claim: %#v", evidence)
					}
				}
			}
			if tc.name == "otlp" && (item.Ordering != "" || item.ExecutionID != "") {
				t.Fatalf("OTLP evidence made unsupported causal or process claims: %#v", item)
			}
		})
	}
}

func TestArtifactRegistryMarksMalformedRecognizedFormat(t *testing.T) {
	result := NewArtifactDecoderRegistry().Ingest(ArtifactDescriptor{ArtifactID: "artifact:bad", Name: "results.xml"}, []byte(`<?xml version="1.0"?><coverage>`))
	if result.Status != ArtifactMalformed || len(result.Evidence) != 0 {
		t.Fatalf("malformed result = %#v", result)
	}
}

func TestNativeGoTraceIsExplicitlyUnsupported(t *testing.T) {
	result := NewArtifactDecoderRegistry().Ingest(ArtifactDescriptor{ArtifactID: "artifact:trace", StorageRef: "artifact://trace"}, []byte("go 1.23 trace\x00\x01binary"))
	if result.Status != ArtifactUnsupported || result.DecoderName != "go-runtime-trace" || len(result.Evidence) != 1 {
		t.Fatalf("native trace result = %#v", result)
	}
	if result.Evidence[0].ClaimKind == "ExecutionTraceObservation" || len(result.Limitations) == 0 {
		t.Fatalf("native trace made unsupported observation claims: %#v", result)
	}
}

func TestTAPArtifactParticipatesInCIFailureClassification(t *testing.T) {
	text := "TAP version 13\n1..1\nnot ok 1 - parser rejects input\n"
	if !isCIEvidenceKind("tap_report") {
		t.Fatal("TAP report is not recognized as CI evidence")
	}
	observations := parseFailureObservations(text)
	if len(observations) != 1 || observations[0].Test != "parser rejects input" {
		t.Fatalf("TAP failure was not normalized: %#v", observations)
	}
}

func TestRuntimeExceptionArtifactParticipatesInCIFailureClassification(t *testing.T) {
	text := "Traceback (most recent call last):\nValueError: bad input\n"
	if !isCIEvidenceKind("runtime_exception_report") {
		t.Fatal("runtime exception is not recognized as CI evidence")
	}
	observations := parseFailureObservations(text)
	if len(observations) != 1 || observations[0].Test != "runtime exception" {
		t.Fatalf("runtime exception was not normalized: %#v", observations)
	}
}

func TestPersistedEvidenceRehydratesArtifactMetadata(t *testing.T) {
	item := evidenceItemFromDomain(domain.Evidence{
		ID: "evidence-1", Type: domain.EvidenceSourceCode, Source: "artifact",
		WorkflowRunID: "workflow-1", ExecutionID: "", BuildID: "build-1", SourceRevision: "rev-1",
		ArtifactID: "artifact-1", ArtifactDigest: "raw-digest", StorageRef: "artifact://raw",
		ParserName: "sarif", ParserVersion: "v1", ArtifactCategory: "static_analysis",
		ArtifactFormat: "sarif", DecoderStatus: "decoded",
	})
	if item.WorkflowRunID != "workflow-1" || item.ExecutionID != "" || item.ArtifactDigest != "raw-digest" || item.ParserName != "sarif" || item.ArtifactFormat != "sarif" {
		t.Fatalf("persisted metadata was dropped during rehydration: %#v", item)
	}
}
