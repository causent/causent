package execution

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yashbhu/Hades/internal/domain"
)

func testPolicy(dir string, timeout time.Duration) Policy {
	return Policy{
		AllowedCommands: map[string]bool{"sh": true, "sleep": true},
		AllowedDirs:     map[string]bool{dir: true},
		AllowedEnviron:  map[string]bool{"PATH": true},
		MaxOutput:       4096,
		Timeout:         timeout,
	}
}

func TestLocalExecutorRunsAllowedCommand(t *testing.T) {
	dir := t.TempDir()
	ex := NewLocalExecutor(testPolicy(dir, 5*time.Second), NewArtifactFactory(filepath.Join(dir, "artifacts")))

	res, err := ex.Run(context.Background(), domain.ExecutionRequest{
		Command:   []string{"sh", "-c", "echo hello"},
		Dir:       dir,
		Timeout:   2 * time.Second,
		MaxOutput: 1024,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d", res.ExitCode)
	}
	if res.Stdout != "hello\n" {
		t.Fatalf("stdout = %q", res.Stdout)
	}
}

func TestLocalExecutorRejectsUnauthorizedCommand(t *testing.T) {
	dir := t.TempDir()
	ex := NewLocalExecutor(testPolicy(dir, 5*time.Second), NewArtifactFactory(filepath.Join(dir, "artifacts")))

	if _, err := ex.Run(context.Background(), domain.ExecutionRequest{
		Command: []string{"rm", "-rf", "/"},
		Dir:     dir,
		Timeout: time.Second,
	}); err == nil {
		t.Fatal("expected policy rejection for unauthorized command")
	}
}

func TestLocalExecutorRejectsEnvironmentLeakage(t *testing.T) {
	dir := t.TempDir()
	ex := NewLocalExecutor(testPolicy(dir, 5*time.Second), NewArtifactFactory(filepath.Join(dir, "artifacts")))

	if _, err := ex.Run(context.Background(), domain.ExecutionRequest{
		Command:   []string{"sh", "-c", "env"},
		Dir:       dir,
		Environ:   []string{"AWS_SECRET_ACCESS_KEY=leak"},
		Timeout:   time.Second,
		MaxOutput: 1024,
	}); err == nil {
		t.Fatal("expected policy rejection for disallowed environment variable")
	}
}

func TestLocalExecutorDoesNotInheritUnexpectedHostEnv(t *testing.T) {
	t.Setenv("HADES_TEST_SECRET", "super-secret-value")
	dir := t.TempDir()
	ex := NewLocalExecutor(testPolicy(dir, 5*time.Second), NewArtifactFactory(filepath.Join(dir, "artifacts")))

	res, err := ex.Run(context.Background(), domain.ExecutionRequest{
		Command:   []string{"sh", "-c", "printf '%s' \"$HADES_TEST_SECRET\""},
		Dir:       dir,
		Timeout:   2 * time.Second,
		MaxOutput: 1024,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(res.Stdout, "super-secret-value") {
		t.Fatalf("host environment leaked into child process: %q", res.Stdout)
	}
}

func TestLocalExecutorRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	p := testPolicy(dir, 5*time.Second)
	p.AllowedDirs[filepath.Join(dir, "..", "escape")] = true
	ex := NewLocalExecutor(p, NewArtifactFactory(filepath.Join(dir, "artifacts")))

	if _, err := ex.Run(context.Background(), domain.ExecutionRequest{
		Command: []string{"sh", "-c", "true"},
		Dir:     filepath.Join(dir, "..", "escape"),
		Timeout: time.Second,
	}); err == nil {
		t.Fatal("expected policy rejection for path traversal")
	}
}

func TestLocalExecutorBoundsOversizedOutput(t *testing.T) {
	dir := t.TempDir()
	ex := NewLocalExecutor(testPolicy(dir, 5*time.Second), NewArtifactFactory(filepath.Join(dir, "artifacts")))

	res, err := ex.Run(context.Background(), domain.ExecutionRequest{
		Command:   []string{"sh", "-c", "printf 'a%.0s' $(seq 1 100000)"},
		Dir:       dir,
		Timeout:   3 * time.Second,
		MaxOutput: 128,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Stdout) != 128 {
		t.Fatalf("expected stdout bounded to 128 bytes, got %d", len(res.Stdout))
	}
}

func TestLocalExecutorTimeout(t *testing.T) {
	dir := t.TempDir()
	ex := NewLocalExecutor(testPolicy(dir, 5*time.Second), NewArtifactFactory(filepath.Join(dir, "artifacts")))

	res, err := ex.Run(context.Background(), domain.ExecutionRequest{
		Command: []string{"sleep", "5"},
		Dir:     dir,
		Timeout: 100 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !res.TimedOut {
		t.Fatal("expected TimedOut to be set")
	}
}

func TestLocalExecutorCancellation(t *testing.T) {
	dir := t.TempDir()
	ex := NewLocalExecutor(testPolicy(dir, 10*time.Second), NewArtifactFactory(filepath.Join(dir, "artifacts")))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	res, err := ex.Run(ctx, domain.ExecutionRequest{
		Command: []string{"sleep", "5"},
		Dir:     dir,
		Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if !res.TimedOut {
		t.Fatal("expected TimedOut to be set on cancellation")
	}
}

func TestPolicyValidate(t *testing.T) {
	p := Policy{
		AllowedCommands: map[string]bool{"sh": true},
		AllowedDirs:     map[string]bool{"/tmp": true},
		AllowedEnviron:  map[string]bool{"PATH": true},
		MaxOutput:       1024,
		Timeout:         5 * time.Second,
	}

	if err := p.Validate("sh", "/tmp", []string{"PATH=/usr/bin"}, 512, time.Second); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		name    string
		cmd     string
		dir     string
		env     []string
		maxOut  int
		timeout time.Duration
	}{
		{"denied command", "rm", "/tmp", []string{"PATH=/usr/bin"}, 512, time.Second},
		{"denied directory", "sh", "/etc", []string{"PATH=/usr/bin"}, 512, time.Second},
		{"denied env", "sh", "/tmp", []string{"SECRET=abc"}, 512, time.Second},
		{"oversized output", "sh", "/tmp", []string{"PATH=/usr/bin"}, 2048, time.Second},
		{"excessive timeout", "sh", "/tmp", []string{"PATH=/usr/bin"}, 512, 10 * time.Second},
		{"forbidden proc", "sh", "/proc/1", []string{"PATH=/usr/bin"}, 512, time.Second},
		{"path traversal", "sh", "/tmp/../etc", []string{"PATH=/usr/bin"}, 512, time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := p.Validate(tc.cmd, tc.dir, tc.env, tc.maxOut, tc.timeout); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestDockerExecutorValidatesBeforeRunning(t *testing.T) {
	dir := t.TempDir()
	p := testPolicy(dir, 5*time.Second)
	cp := CollectPolicy{Image: "golang:1.22", MaxOutput: 4096, Timeout: 5 * time.Second, MemoryLimitMB: 512, CPULimitPercent: 50, ProcessLimit: 128}
	ex := NewDockerExecutor(p, NewArtifactFactory(filepath.Join(dir, "artifacts")), cp)

	// Missing workspace must be rejected before any docker invocation.
	if _, err := ex.Run(context.Background(), domain.ExecutionRequest{
		Command: []string{"sh", "-c", "true"},
		Dir:     dir,
		Timeout: time.Second,
	}); err == nil {
		t.Fatal("expected error for missing workspace path")
	}

	// Workspace escape via ".." must be rejected.
	if _, err := ex.Run(context.Background(), domain.ExecutionRequest{
		Command:       []string{"sh", "-c", "true"},
		Dir:           dir,
		WorkspacePath: filepath.Join(dir, "..", "escape"),
		InstanceID:    "escape-test",
		Timeout:       time.Second,
	}); err == nil {
		t.Fatal("expected error for workspace path traversal")
	}

	// A missing image must be rejected rather than letting the command name be
	// interpreted as the image by `docker run`.
	noImage := NewDockerExecutor(p, NewArtifactFactory(filepath.Join(dir, "artifacts")), CollectPolicy{})
	if _, err := noImage.Run(context.Background(), domain.ExecutionRequest{
		Command:       []string{"go", "test", "./..."},
		Dir:           dir,
		WorkspacePath: dir,
		InstanceID:    "no-image",
	}); err == nil {
		t.Fatal("expected error for missing container image")
	}
}

func TestDockerExecutorContainerArgs(t *testing.T) {
	dir := t.TempDir()
	cp := CollectPolicy{Image: "golang:1.22", MaxOutput: 4096, Timeout: time.Minute, MemoryLimitMB: 512, CPULimitPercent: 50, ProcessLimit: 128}
	ex := NewDockerExecutor(testPolicy(dir, time.Minute), nil, cp)

	name := containerName("inst/with spaces:1")
	if !strings.HasPrefix(name, "hades-exec-inst-with-spaces-1-") {
		t.Fatalf("unexpected container name %q", name)
	}
	if strings.ContainsAny(name, " /:") {
		t.Fatalf("container name contains invalid characters: %q", name)
	}

	env := []string{"HOME=/tmp", "TMPDIR=/tmp", "PATH=/usr/bin"}
	args := strings.Join(ex.containerArgs(name, "/workspace", dir, env), "\x00")
	joined := strings.ReplaceAll(args, "\x00", " ")

	for _, want := range []string{
		"run --rm ",
		" --init ",
		" --name " + name + " ",
		" --workdir /workspace ",
		" --mount type=bind,source=" + dir + ",target=/workspace ",
		" --tmpfs /tmp:rw,exec,nosuid,nodev ",
		" --network none ",
		" --read-only ",
		" --cap-drop ALL ",
		" --security-opt no-new-privileges ",
		" --memory 512m ",
		" --memory-swap 1024m ",
		" --cpu-quota 50000 ",
		" --pids-limit 128 ",
		" --env HOME=/tmp ",
		" --env PATH=/usr/bin ",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("container args missing %q in: %s", want, joined)
		}
	}

	// The image must terminate the option list, and the command must follow it.
	last := ex.containerArgs(name, "/workspace", dir, env)
	if last[len(last)-1] != "golang:1.22" {
		t.Fatalf("expected image as final argument, got %q", last[len(last)-1])
	}
	if strings.Contains(joined, "--detach") {
		t.Fatal("detached mode would return before the command completes")
	}
	if strings.Contains(joined, ",ro ") {
		t.Fatal("read-only workspace mount would break build output")
	}
}

func TestCollectPolicyValidate(t *testing.T) {
	cp := CollectPolicy{Image: "golang:1.22", MaxOutput: 4096, Timeout: 5 * time.Second, MemoryLimitMB: 512, CPULimitPercent: 50, ProcessLimit: 128}

	if err := cp.Validate([]string{"go", "test"}, "/tmp", []string{"PATH=/usr/bin"}, 1024, time.Second); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := cp.Validate([]string{"curl", "http://example.com"}, "/tmp", nil, 1024, time.Second); err == nil {
		t.Fatal("expected error for disallowed command")
	}
	if err := cp.Validate([]string{"go", "test"}, "relative/path", nil, 1024, time.Second); err == nil {
		t.Fatal("expected error for relative working directory")
	}
}

func TestArtifactFactoryDigestVerification(t *testing.T) {
	dir := t.TempDir()
	af := NewArtifactFactory(filepath.Join(dir, "artifacts"))

	art, err := af.Create(domain.NewID(), "stdout", []byte("test data"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	data, err := af.ReadArtifact(art)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "test data" {
		t.Fatalf("read = %q", string(data))
	}

	if err := os.WriteFile(filepath.Join(dir, "artifacts", art.Path), []byte("corrupted"), 0600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if _, err := af.ReadArtifact(art); err == nil {
		t.Fatal("expected digest mismatch error")
	}
}

func TestArtifactFactoryRejectsEscapingPath(t *testing.T) {
	dir := t.TempDir()
	af := NewArtifactFactory(filepath.Join(dir, "artifacts"))

	_, err := af.ReadArtifact(&domain.Artifact{Path: "../../etc/passwd", Digest: "x"})
	if err == nil {
		t.Fatal("expected error reading artifact outside root")
	}
	if !strings.Contains(err.Error(), "escapes artifact root") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestArtifactFactorySizeLimit(t *testing.T) {
	dir := t.TempDir()
	af := NewArtifactFactory(filepath.Join(dir, "artifacts"))

	if _, err := af.Create(domain.NewID(), "stdout", make([]byte, MaxArtifactSize+1)); err == nil {
		t.Fatal("expected error for oversized artifact")
	}
}
