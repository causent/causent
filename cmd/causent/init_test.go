package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectorFixtures(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"go", map[string]string{"go.mod": "module example\ngo 1.26\n"}, []string{"Go", "Go 1.26"}},
		{"node", map[string]string{"package.json": "{\"scripts\":{\"test\":\"vitest\"}}\n", "package-lock.json": "{}\n"}, []string{"Node.js", "npm test"}},
		{"python", map[string]string{"pyproject.toml": "[project]\nname='x'\n", "requirements.txt": "pytest\n"}, []string{"Python", "pip"}},
		{"rust", map[string]string{"Cargo.toml": "[package]\nname='x'\n"}, []string{"Rust", "Cargo"}},
		{"bazel", map[string]string{"MODULE.bazel": "module(name='x')\n"}, []string{"Bazel"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, body := range tt.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			d, err := (detector{}).Detect(dir)
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			for _, f := range append(append([]Finding{}, d.Languages...), append(d.BuildSystems, d.PackageManagers...)...) {
				got += " " + f.Name
			}
			for _, want := range tt.want {
				found := strings.Contains(got, want)
				for _, f := range d.RuntimeVersions {
					found = found || strings.Contains(f.Name, want)
				}
				for _, f := range d.TestCommands {
					found = found || strings.Contains(f.Name, want)
				}
				if !found {
					t.Errorf("missing %q in %q", want, got)
				}
			}
		})
	}
}

func TestDetectorUsesWorkflowEvidenceAndMultipleLanguages(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"go.mod": "module x\n", "pyproject.toml": "[project]\nname='x'\n", ".github/workflows/ci.yml": "name: CI\njobs:\n  test:\n    steps:\n      - run: go test ./...\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := (detector{}).Detect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Languages) != 2 || len(d.CIProviders) != 1 || len(d.TestCommands) != 1 || d.TestCommands[0].Name != "go test ./..." {
		t.Fatalf("unexpected detection: %+v", d)
	}
}

func TestInitWorkflowAndConfigAreSupported(t *testing.T) {
	d := RepositoryDetection{Workflows: []Finding{{Name: "CI", Evidence: "ci.yml"}}, TestCommands: []Finding{{Name: "go test ./..."}}}
	if got := renderInitConfig(d); !strings.Contains(got, "command: \"go test ./...\"") || strings.Contains(got, "language:") {
		t.Fatalf("unexpected config: %s", got)
	}
	w := renderInitWorkflow(d)
	for _, want := range []string{"workflow_run:", "workflows: [CI]", "causent/causent/.github/workflows/ci-diagnose.yml@v1", "run_id:"} {
		if !strings.Contains(w, want) {
			t.Errorf("workflow missing %q", want)
		}
	}
	if strings.Contains(w, "workflow_run.base_sha") || !strings.Contains(w, "pull_requests[0].base.sha") {
		t.Fatalf("workflow must pass the exact pull request base SHA: %s", w)
	}
}
