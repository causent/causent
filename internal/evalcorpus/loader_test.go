package evalcorpus

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExampleCorpusLoadsAndValidates(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..", "evaluation", "corpus")
	_, cases, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1 || cases[0].Input.FailureLog == "" {
		t.Fatalf("unexpected cases: %+v", cases)
	}
	if err := ValidateExpectedFile(filepath.Join(cases[0].Dir, "expected.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestLoaderRejectsUnknownMetadataAndInvalidFullCase(t *testing.T) {
	root := t.TempDir()
	caseDir := filepath.Join(root, "cases", "bad")
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "manifest.yaml"), "version: '1'\ncases:\n  - id: bad\n    tier: full\n    category: regression\n")
	write(filepath.Join(caseDir, "metadata.yaml"), "id: bad\ntier: full\ncategory: regression\nrepo: repo\nrun_url: run\nlog_sha256: abc\nlicense_note: test\nredacted: true\nunknown: value\n")
	if _, _, err := Load(root); err == nil || !strings.Contains(err.Error(), "field unknown") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
	write(filepath.Join(caseDir, "metadata.yaml"), "id: bad\ntier: full\ncategory: regression\nrepo: repo\nrun_url: run\nlog_sha256: 3c761e66bd0dfb3d1c99eee29b3b39be6e387af53ade673bf4d532abc4b6ed46\nlicense_note: test\nredacted: true\n")
	if _, _, err := Load(root); err == nil || !strings.Contains(err.Error(), "full cases require") {
		t.Fatalf("expected full-tier validation error, got %v", err)
	}
}

func TestExpectedReaderIsOwnedByScorer(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	packageDir := filepath.Dir(file)
	needle := "expected." + "yaml"
	err := filepath.Walk(packageDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(filepath.Base(path), "_test.go") || filepath.Base(path) == "scorer.go" {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(data), needle) {
			t.Fatalf("%s reads ground-truth file outside scorer.go", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
