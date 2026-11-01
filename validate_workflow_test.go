package causent_test

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func readWorkflow(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestCIIntegrationTriggerIsValid(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/ci-integration.yml")
	if err != nil {
		t.Fatalf("read ci-integration.yml: %v", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse ci-integration.yml: %v", err)
	}
	root := doc.Content[0]
	on := mapKey(root, "on")
	if on == nil {
		t.Fatal("ci-integration.yml has no on trigger")
	}
	workflowRun := mapKey(on, "workflow_run")
	if workflowRun == nil {
		t.Fatal("ci-integration.yml has no workflow_run trigger")
	}
	if mapKey(workflowRun, "if") != nil {
		t.Fatal("workflow_run must not contain if; conditions belong at job level")
	}
	job := mapKey(mapKey(root, "jobs"), "diagnose")
	if job == nil || mapKey(job, "if") == nil {
		t.Fatal("ci-integration.yml must filter failures with a job-level if")
	}
	if !strings.Contains(string(data), "pull_requests[0].base.sha") {
		t.Fatal("ci-integration.yml must pass the pull request base SHA")
	}
	if !strings.Contains(string(data), "issues: write") {
		t.Fatal("ci-integration.yml must grant comment publication permission")
	}
}

func TestReusableWorkflowContract(t *testing.T) {
	content := readWorkflow(t, ".github/workflows/ci-diagnose.yml")
	checks := map[string]bool{
		"workflow_call trigger":                       strings.Contains(content, "workflow_call"),
		"head_sha input":                              strings.Contains(content, "head_sha:"),
		"base_sha input":                              strings.Contains(content, "base_sha:"),
		"base_ref input":                              strings.Contains(content, "base_ref:"),
		"run_id input":                                strings.Contains(content, "run_id:"),
		"checks out failing commit":                   strings.Contains(content, "github.event.workflow_run.head_sha"),
		"fetches failed logs":                         strings.Contains(content, "--log-failed"),
		"installs released binary":                    strings.Contains(content, "releases/latest/download/causent_linux_amd64"),
		"passes base revision":                        strings.Contains(content, "--base"),
		"passes docker executor":                      strings.Contains(content, "--executor docker"),
		"passes attempts":                             strings.Contains(content, "--attempts"),
		"uploads bundle":                              strings.Contains(content, "actions/upload-artifact"),
		"writes job summary":                          strings.Contains(content, "GITHUB_STEP_SUMMARY"),
		"comments on PR":                              strings.Contains(content, "gh pr comment"),
		"does not persist checkout credentials":       strings.Contains(content, "persist-credentials: false"),
		"passes original CI log":                      strings.Contains(content, "--ci-log"),
		"separate publication job":                    strings.Contains(content, "publish:"),
		"publication can write issue comments":        strings.Contains(content, "issues: write"),
		"does not expose gateway secret to diagnosis": !strings.Contains(content, "CAUSENT_GATEWAY_ENDPOINT: ${{ secrets"),
		"validates release version":                   strings.Contains(content, "invalid causent_version"),
		"validates release repository":                strings.Contains(content, "invalid causent_repository"),
		"redacts bearer tokens":                       strings.Contains(content, "bearer"),
		"redacts GitHub tokens":                       strings.Contains(content, "gh[pousr]_") && strings.Contains(content, "github_pat_"),
	}
	for check, passed := range checks {
		if !passed {
			t.Errorf("reusable workflow check failed: %s", check)
		}
	}
}

func TestManualDiagnosisWorkflow(t *testing.T) {
	content := readWorkflow(t, ".github/workflows/diagnosis.yml")
	checks := map[string]bool{
		"workflow_dispatch trigger": strings.Contains(content, "workflow_dispatch"),
		"failing_command input":     strings.Contains(content, "failing_command"),
		"attempts input":            strings.Contains(content, "attempts"),
		"docker_image input":        strings.Contains(content, "docker_image"),
		"uses reusable workflow":    strings.Contains(content, "./.github/workflows/ci-diagnose.yml"),
	}
	for check, passed := range checks {
		if !passed {
			t.Errorf("diagnosis workflow check failed: %s", check)
		}
	}
}

func TestReleaseWorkflowPublishesBinary(t *testing.T) {
	content := readWorkflow(t, ".github/workflows/release.yml")
	checks := map[string]bool{
		"tag trigger":         strings.Contains(content, "tags:"),
		"builds causent":      strings.Contains(content, "./cmd/causent"),
		"stamps version":      strings.Contains(content, "-X main.version="),
		"publishes release":   strings.Contains(content, "action-gh-release"),
		"publishes checksums": strings.Contains(content, "SHA256SUMS"),
	}
	for check, passed := range checks {
		if !passed {
			t.Errorf("release workflow check failed: %s", check)
		}
	}
}

func TestRepoConfigExample(t *testing.T) {
	content := readWorkflow(t, ".causent.yml")
	if !strings.Contains(content, "command:") {
		t.Fatal(".causent.yml must document the command key")
	}
}

// mapKey returns the value node for key in a mapping node.
func mapKey(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
