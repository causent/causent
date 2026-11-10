package malenia_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProwEvidenceResolverContracts(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		curlScript string
		available  string
		reason     string
	}{
		{
			name:       "valid URL downloads expected log",
			url:        "https://prow.k8s.io/view/gs/bucket/build-123",
			curlScript: "printf '=== FAIL: TestRace\\n'",
			available:  "true",
		},
		{
			name:      "missing URL does not fall back to reproduction",
			available: "false",
			reason:    "No failed source CI run or supported Prow status context",
		},
		{
			name:      "invalid URL is rejected",
			url:       "https://example.invalid/ci/build-123",
			available: "false",
			reason:    "not a supported Prow GS URL",
		},
		{
			name:       "inaccessible URL is reported",
			url:        "https://prow.k8s.io/view/gs/bucket/build-404",
			curlScript: "exit 22",
			available:  "false",
			reason:     "Could not read Prow log",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			temp := t.TempDir()
			bin := filepath.Join(temp, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			writeExecutable(t, filepath.Join(bin, "gh"), "#!/bin/sh\nexit 0\n")
			curlScript := test.curlScript
			if curlScript == "" {
				curlScript = "exit 0"
			}
			writeExecutable(t, filepath.Join(bin, "curl"), "#!/bin/sh\n"+curlScript+"\n")
			output := filepath.Join(temp, "github-output")
			cmd := exec.Command("bash", ".github/scripts/resolve-source-evidence.sh")
			cmd.Env = append(os.Environ(),
				"PATH="+bin+":"+os.Getenv("PATH"),
				"TARGET_REPOSITORY=kubernetes/kubernetes",
				"HEAD_SHA=head-123",
				"SOURCE_RUN_ID=",
				"SOURCE_CI_URL="+test.url,
				"RUNNER_TEMP="+temp,
				"GITHUB_OUTPUT="+output,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("resolver failed: %v\n%s", err, out)
			}
			outputData, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			outputText := string(outputData)
			if !strings.Contains(outputText, "available="+test.available) {
				t.Fatalf("output=%q, want available=%s", outputText, test.available)
			}
			status, err := os.ReadFile(filepath.Join(temp, "source-evidence-status.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if test.reason != "" && !strings.Contains(string(status), test.reason) {
				t.Fatalf("status=%q, want reason containing %q", status, test.reason)
			}
			if test.available == "true" {
				if !strings.Contains(outputText, "build_id=build-123") || !strings.Contains(outputText, "bounded_log_path=") {
					t.Fatalf("Prow provenance/path outputs missing: %q", outputText)
				}
				bounded := outputValue(outputText, "bounded_log_path")
				if data, err := os.ReadFile(bounded); err != nil || !strings.Contains(string(data), "CI evidence") {
					t.Fatalf("bounded evidence path=%q data=%q err=%v", bounded, data, err)
				}
				if data, err := os.Stat(filepath.Join(temp, "source-ci.log")); err != nil || data.Size() == 0 {
					t.Fatalf("expected downloaded source log: stat=%v", err)
				}
			}
		})
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func outputValue(output, key string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, key+"=") {
			return strings.TrimPrefix(line, key+"=")
		}
	}
	return ""
}
