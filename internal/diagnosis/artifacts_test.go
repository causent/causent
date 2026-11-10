package diagnosis

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
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
