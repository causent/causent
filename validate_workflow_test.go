package hades_test

import (
	"os"
	"strings"
	"testing"
)

func TestWorkflowValidation(t *testing.T) {
	data, err := os.ReadFile(".github/workflows/diagnosis.yml")
	if err != nil {
		t.Fatalf("read diagnosis.yml: %v", err)
	}
	content := string(data)

	checks := map[string]bool{
		"base_ref input":               strings.Contains(content, "base_ref"),
		"head_ref input":               strings.Contains(content, "head_ref"),
		"failing_command input":        strings.Contains(content, "failing_command"),
		"attempts input":               strings.Contains(content, "attempts"),
		"docker_image input":           strings.Contains(content, "docker_image"),
		"runs-on: ubuntu-latest":       strings.Contains(content, "runs-on: ubuntu-latest"),
		"workflow_dispatch trigger":    strings.Contains(content, "workflow_dispatch"),
		"cypher diagnose command":      strings.Contains(content, "cypher diagnose"),
		"--executor docker":            strings.Contains(content, "--executor docker"),
		"--image":                      strings.Contains(content, "--image"),
		"--base":                       strings.Contains(content, "--base"),
		"--agent":                      strings.Contains(content, "--agent"),
		"actions/upload-artifact":      strings.Contains(content, "actions/upload-artifact"),
		"GITHUB_STEP_SUMMARY":          strings.Contains(content, "GITHUB_STEP_SUMMARY"),
		"classification summary":       strings.Contains(content, "Classification"),
		"base/head pass-fail":          strings.Contains(content, "base_fail"),
		"confidence summary":          strings.Contains(content, "confidence"),
		"bundle location":              strings.Contains(content, "Bundle Location"),
	}

	for check, passed := range checks {
		if !passed {
			t.Errorf("workflow validation check failed: %s", check)
		}
	}
}
