package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadArtifactEvidenceBoundsAndRedacts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "junit.xml")
	if err := os.WriteFile(path, []byte(`<testsuite><testcase name="broken"><failure message="token=secret">run.go:12</failure></testcase></testsuite>`), 0o600); err != nil {
		t.Fatal(err)
	}

	evidence, err := loadArtifactEvidence(dir, 20, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 {
		t.Fatalf("got %d evidence items, want 1", len(evidence))
	}
	if evidence[0].Kind != "junit_report" {
		t.Fatalf("kind = %q, want junit_report", evidence[0].Kind)
	}
	if evidence[0].Provenance == "" {
		t.Fatal("expected provenance")
	}
	if evidence[0].Detail == "" || containsSecret(evidence[0].Detail) {
		t.Fatalf("artifact was not safely retained: %q", evidence[0].Detail)
	}
}

func TestLoadArtifactEvidenceRecordsUnreadableLimits(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "large.log"), []byte("failure\nextra"), 0o600); err != nil {
		t.Fatal(err)
	}

	evidence, err := loadArtifactEvidence(dir, 20, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != 1 || evidence[0].Kind != "ci_artifact_manifest" {
		t.Fatalf("got %#v, want a limitations manifest", evidence)
	}
	if len(evidence[0].Limitations) == 0 {
		t.Fatal("expected ingestion limitation")
	}
}

func containsSecret(value string) bool {
	return strings.Contains(value, "token=secret")
}
