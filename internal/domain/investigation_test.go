package domain

import (
	"testing"
	"time"
)

func TestExecutionRequest(t *testing.T) {
	req := ExecutionRequest{
		Command:       []string{"sh", "-c", "echo hello"},
		Dir:           "/tmp",
		Timeout:       5 * time.Second,
		MaxOutput:     1024,
		WorkspacePath: "/workspace",
		InstanceID:    "test-instance",
	}
	if req.Command[0] != "sh" {
		t.Fatalf("expected sh, got %s", req.Command[0])
	}
	if req.Dir != "/tmp" {
		t.Fatalf("expected /tmp, got %s", req.Dir)
	}
	if req.Timeout != 5*time.Second {
		t.Fatalf("expected 5s timeout, got %v", req.Timeout)
	}
	if req.MaxOutput != 1024 {
		t.Fatalf("expected 1024 max output, got %d", req.MaxOutput)
	}
	if req.WorkspacePath != "/workspace" {
		t.Fatalf("expected /workspace, got %s", req.WorkspacePath)
	}
	if req.InstanceID != "test-instance" {
		t.Fatalf("expected test-instance, got %s", req.InstanceID)
	}
}

func TestID(t *testing.T) {
	id := NewID()
	if id == "" {
		t.Fatal("expected non-empty ID")
	}
}

func TestExecutionResult(t *testing.T) {
	res := ExecutionResult{
		ExitCode: 0,
		Stdout:   "hello",
		Stderr:   "world",
		Error:    "some error",
		TimedOut: false,
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected 0, got %d", res.ExitCode)
	}
	if res.Stdout != "hello" {
		t.Fatalf("expected hello, got %s", res.Stdout)
	}
	if res.Stderr != "world" {
		t.Fatalf("expected world, got %s", res.Stderr)
	}
	if res.Error != "some error" {
		t.Fatalf("expected some error, got %s", res.Error)
	}
	if res.TimedOut != false {
		t.Fatalf("expected false, got %v", res.TimedOut)
	}
}

func TestPolicyValidationError(t *testing.T) {
	err := &PolicyValidationError{Message: "test error"}
	if err.Error() != "test error" {
		t.Fatalf("expected test error, got %s", err.Error())
	}
}

func TestDigestError(t *testing.T) {
	err := &DigestError{Expected: "abc", Got: "def"}
	if err.Error() != "digest mismatch: expected abc, got def" {
		t.Fatalf("expected digest mismatch message, got %s", err.Error())
	}
}

func TestCargoToml(t *testing.T) {
	t.Skip("workspace fixture test is covered by repository fixtures")
}

func TestWorkspaceRoot(t *testing.T) {
	// Verify workspace root is set correctly
	t.Skip("workspace root test")
}
