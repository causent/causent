package execution

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/causent/causent/internal/domain"
)

// Policy defines the security constraints for a command execution.
type Policy struct {
	// AllowedCommands is the set of executable names permitted.
	AllowedCommands map[string]bool
	// AllowedDirs is the set of directories the command may run in.
	AllowedDirs        map[string]bool
	AllowedDirPrefixes []string
	// AllowedEnviron is the set of environment variable names permitted.
	AllowedEnviron map[string]bool
	// MaxOutput is the maximum output size in bytes.
	MaxOutput int
	// Timeout is the execution timeout.
	Timeout time.Duration
	// BlockPaths is a list of path prefixes that are forbidden.
	BlockPaths []string
}

// Validate validates a request against a policy.
func (p Policy) Validate(cmd string, dir string, env []string, maxOut int, timeout time.Duration) error {
	if !p.AllowedCommands[cmd] {
		return fmt.Errorf("command %q not allowed by policy", cmd)
	}
	if !p.AllowedDirs[dir] && !withinAllowedPrefix(dir, p.AllowedDirPrefixes) {
		return fmt.Errorf("directory %q not allowed by policy", dir)
	}

	for _, pair := range env {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) > 0 && !p.AllowedEnviron[parts[0]] {
			return fmt.Errorf("environment variable %q not allowed by policy", parts[0])
		}
	}
	if maxOut > p.MaxOutput {
		return fmt.Errorf("output limit %d exceeds policy max %d", maxOut, p.MaxOutput)
	}
	if timeout > p.Timeout {
		return fmt.Errorf("timeout %v exceeds policy timeout %v", timeout, p.Timeout)
	}
	if strings.HasPrefix(dir, "/proc") || strings.HasPrefix(dir, "/sys") {
		return fmt.Errorf("directory %q is forbidden", dir)
	}
	if strings.Contains(dir, "..") {
		return fmt.Errorf("path %q contains forbidden '..'", dir)
	}
	return nil
}

func withinAllowedPrefix(dir string, prefixes []string) bool {
	for _, prefix := range prefixes {
		rel, err := filepath.Rel(prefix, dir)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return true
		}
	}
	return false
}

// Executor executes commands under a policy.
type Executor interface {
	Run(ctx context.Context, req domain.ExecutionRequest) (domain.ExecutionResult, error)
}

// Request is an alias for domain.ExecutionRequest.
type Request = domain.ExecutionRequest

// ArtifactFactory creates and tracks artifacts.
type ArtifactFactory struct {
	root string
}

// NewArtifactFactory creates an artifact factory with the given root directory.
func NewArtifactFactory(root string) *ArtifactFactory {
	return &ArtifactFactory{root: root}
}

// MaxArtifactSize is the maximum size of a single stored artifact.
const MaxArtifactSize = int64(100 << 20) // 100 MB

// Create creates a new artifact in the factory's root.
func (af *ArtifactFactory) Create(invID domain.ID, kind string, data []byte) (*domain.Artifact, error) {
	//Validate size
	if int64(len(data)) > MaxArtifactSize {
		return nil, fmt.Errorf("artifact data too large: %d bytes", len(data))
	}
	//Compute digest
	digest := digest(data)
	//Create directory
	dir := filepath.Join(af.root, string(invID))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	name := hex.EncodeToString([]byte(invID)) + "_" + time.Now().UTC().Format("20060102T150405.000000000") + "_" + kind
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	slog.Info("artifact stored", "investigation_id", string(invID), "type", kind, "size", info.Size())
	art := &domain.Artifact{
		ID:              domain.NewID(),
		InvestigationID: invID,
		Type:            kind,
		Path:            filepath.Join(string(invID), name),
		Size:            info.Size(),
		Digest:          digest,
		CreatedAt:       time.Now().UTC(),
	}
	return art, nil
}

// ReadArtifact reads an artifact and verifies its digest.
func (af *ArtifactFactory) ReadArtifact(art *domain.Artifact) ([]byte, error) {
	//Reject references that escape the artifact root
	rel := filepath.Clean(art.Path)
	if filepath.IsAbs(rel) || strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("artifact path escapes artifact root: %q", art.Path)
	}
	absPath := filepath.Join(af.root, rel)
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxArtifactSize {
		return nil, fmt.Errorf("artifact too large: %d bytes", len(data))
	}
	digest := digest(data)
	if digest != art.Digest {
		return nil, fmt.Errorf("artifact digest mismatch: expected %s, got %s", art.Digest, digest)
	}
	return data, nil
}

func digest(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// LocalExecutor executes commands locally with policy enforcement.
type LocalExecutor struct {
	policy          Policy
	artifactFactory *ArtifactFactory
}

// NewLocalExecutor creates a new local executor.
func NewLocalExecutor(policy Policy, artifactFactory *ArtifactFactory) *LocalExecutor {
	return &LocalExecutor{
		policy:          policy,
		artifactFactory: artifactFactory,
	}
}

// Run executes a command with the given request and returns the result.
func (e *LocalExecutor) Run(ctx context.Context, req domain.ExecutionRequest) (domain.ExecutionResult, error) {
	if len(req.Command) == 0 {
		return domain.ExecutionResult{}, fmt.Errorf("command is required")
	}
	//Validate policy
	if err := e.policy.Validate(req.Command[0], req.Dir, req.Environ, req.MaxOutput, req.Timeout); err != nil {
		return domain.ExecutionResult{}, err
	}
	//Enforce the requested timeout
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	//Create command
	c := exec.CommandContext(ctx, req.Command[0], req.Command[1:]...)
	c.Dir = req.Dir
	c.Env = e.buildEnv(req.Environ)
	c.Stdin = nil
	c.Stdout = nil
	c.Stderr = nil
	//Limit output
	maxOut := req.MaxOutput
	if maxOut == 0 {
		maxOut = e.policy.MaxOutput
	}
	//Capture stdout and stderr
	var stdoutBuf, stderrBuf strings.Builder

	c.Stdout = &stdoutBuf
	c.Stderr = &stderrBuf

	//Start command
	started := time.Now()
	if err := c.Start(); err != nil {
		slog.Warn("execution failed to start", "command", req.Command[0], "dir", req.Dir, "error", err)
		return domain.ExecutionResult{}, err
	}

	//Wait for command with timeout
	done := make(chan error, 1)
	go func() {
		done <- c.Wait()
	}()

	select {
	case err := <-done:
		stdout := stdoutBuf.String()
		stderr := stderrBuf.String()
		result := domain.ExecutionResult{
			ExitCode:   c.ProcessState.ExitCode(),
			Stdout:     boundOutput(stdout, maxOut),
			Stderr:     boundOutput(stderr, maxOut),
			TimedOut:   false,
			Duration:   time.Since(started),
			StartedAt:  started,
			FinishedAt: time.Now(),
		}
		if err != nil {
			if ctx.Err() != nil {
				result.TimedOut = true
			} else {
				result.TimedOut = false
				result.Error = err.Error()
			}
		}
		slog.Debug("execution completed",
			"command", req.Command[0],
			"dir", req.Dir,
			"exit_code", result.ExitCode,
			"stdout_bytes", len(stdout),
			"stderr_bytes", len(stderr),
			"duration", result.Duration.String())
		return result, nil
	case <-ctx.Done():
		c.Process.Kill()
		slog.Warn("execution cancelled", "command", req.Command[0], "dir", req.Dir, "after", time.Since(started).String())
		return domain.ExecutionResult{
			ExitCode:  -1,
			Stdout:    boundOutput(stdoutBuf.String(), maxOut),
			Stderr:    boundOutput(stderrBuf.String(), maxOut),
			TimedOut:  true,
			Duration:  time.Since(started),
			StartedAt: started,
		}, ctx.Err()
	}
}

// buildEnv constructs the child environment from the policy allow-list so that
// unrelated host variables (tokens, credentials) are not inherited.
func (e *LocalExecutor) buildEnv(extra []string) []string {
	env := make([]string, 0, len(e.policy.AllowedEnviron)+len(extra))
	for _, pair := range os.Environ() {
		name, _, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if e.policy.AllowedEnviron[name] {
			env = append(env, pair)
		}
	}
	hasPath := false
	for _, pair := range env {
		if strings.HasPrefix(pair, "PATH=") {
			hasPath = true
			break
		}
	}
	if !hasPath {
		env = append(env, "PATH=/usr/local/bin:/usr/bin:/bin")
	}
	return append(env, extra...)
}

// boundOutput truncates the output to max bytes.
func boundOutput(s string, max int) string {
	if max == 0 {
		return s
	}
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// DockerExecutor executes commands in a Docker container.
type DockerExecutor struct {
	policy          Policy
	artifactFactory *ArtifactFactory
	collectPolicy   CollectPolicy
}

// NewDockerExecutor creates a new Docker executor.
func NewDockerExecutor(policy Policy, artifactFactory *ArtifactFactory, collectPolicy CollectPolicy) *DockerExecutor {
	return &DockerExecutor{
		policy:          policy,
		artifactFactory: artifactFactory,
		collectPolicy:   collectPolicy,
	}
}

// Run executes a command inside a Docker container.
func (e *DockerExecutor) Run(ctx context.Context, req domain.ExecutionRequest) (domain.ExecutionResult, error) {
	if len(req.Command) == 0 {
		return domain.ExecutionResult{}, fmt.Errorf("command is required")
	}
	//Validate policy
	if err := e.policy.Validate(req.Command[0], req.Dir, req.Environ, req.MaxOutput, req.Timeout); err != nil {
		return domain.ExecutionResult{}, err
	}
	//Enforce the requested timeout
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	//Set up workspace
	workdir := req.Dir
	workspacePath := req.WorkspacePath
	instanceID := req.InstanceID

	//Validate workspace
	if workspacePath == "" {
		return domain.ExecutionResult{}, fmt.Errorf("workspace path required")
	}
	if !filepath.IsAbs(workspacePath) {
		return domain.ExecutionResult{}, fmt.Errorf("workspace path must be absolute: %s", workspacePath)
	}

	//Prevent path traversal
	if strings.Contains(workspacePath, "..") {
		return domain.ExecutionResult{}, fmt.Errorf("workspace path contains forbidden '..': %s", workspacePath)
	}

	//Validate instance ID
	if instanceID == "" {
		return domain.ExecutionResult{}, fmt.Errorf("instance ID required")
	}

	//Validate collect policy once the request shape is known.
	if err := e.collectPolicy.Validate(req.Command, req.Dir, req.Environ, req.MaxOutput, req.Timeout); err != nil {
		return domain.ExecutionResult{}, err
	}

	//Prepare container command
	containerCmd := req.Command
	if len(containerCmd) == 0 {
		return domain.ExecutionResult{}, fmt.Errorf("command required")
	}

	//Set working directory
	wd := workdir
	if wd == "" {
		wd = "/workspace"
	}
	if !filepath.IsAbs(wd) {
		wd = filepath.Join("/", wd)
	}

	//Container environment. HOME/TMPDIR point at the writable tmpfs so
	//toolchains (go build cache, pip, cargo) can write despite --read-only.
	env := []string{"HOME=/tmp", "TMPDIR=/tmp"}
	env = append(env, req.Environ...)

	name := containerName(instanceID)
	args := e.containerArgs(name, wd, workspacePath, env)
	args = append(args, req.Command...)

	//Execute container
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return domain.ExecutionResult{}, fmt.Errorf("docker start: %w", err)
	}
	startedAt := time.Now()

	//Wait for result
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		stdout := stdoutBuf.String()
		stderr := stderrBuf.String()
		result := domain.ExecutionResult{
			ExitCode:   cmd.ProcessState.ExitCode(),
			Stdout:     boundOutput(stdout, req.MaxOutput),
			Stderr:     boundOutput(stderr, req.MaxOutput),
			TimedOut:   false,
			Duration:   time.Since(startedAt),
			StartedAt:  startedAt,
			FinishedAt: time.Now(),
		}
		// docker exits 125 for daemon/CLI failures (bad image, no daemon),
		// which is not a test failure and must not look like one.
		if result.ExitCode == 125 {
			result.Error = "docker could not start the container: " + strings.TrimSpace(stderr)
		} else if err != nil && ctx.Err() == nil {
			result.Error = err.Error()
		}
		return result, nil
	case <-ctx.Done():
		res := domain.ExecutionResult{
			ExitCode:  -1,
			Stdout:    boundOutput(stdoutBuf.String(), req.MaxOutput),
			Stderr:    boundOutput(stderrBuf.String(), req.MaxOutput),
			TimedOut:  true,
			StartedAt: startedAt,
		}
		//Cleanup is best effort; failures are reported, not silently ignored.
		if cleanupErr := e.cleanupContainer(ctx, name); cleanupErr != nil {
			res.Error = "container cleanup failed: " + cleanupErr.Error()
			slog.Warn("container cleanup failed", "container", name, "error", cleanupErr)
		}
		//The docker CLI may still be waiting; --rm plus the explicit rm above
		//guarantee the container itself is gone.
		<-done
		return res, ctx.Err()
	}
}

// containerName derives a unique, docker-safe container name so concurrent
// runs of the same instance cannot collide.
func containerName(instanceID string) string {
	var b strings.Builder
	for _, r := range instanceID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
		if b.Len() >= 40 {
			break
		}
	}
	buf := make([]byte, 3)
	_, _ = rand.Read(buf)
	return "causent-exec-" + b.String() + "-" + hex.EncodeToString(buf)
}

// containerArgs builds the `docker run` argument list (everything before the
// command). It is a pure function so the invocation can be asserted without a
// running daemon.
func (e *DockerExecutor) containerArgs(name, wd, workspacePath string, env []string) []string {
	args := []string{
		"run",
		"--rm",
		"--init",
		"--name", name,
		"--workdir", wd,
		// The candidate workspace is a disposable copy owned by the caller, so
		// it is mounted read-write: toolchains write build output inside the
		// tree (target/, node_modules/). /tmp gets its own tmpfs because the
		// container root filesystem is read-only.
		"--mount", fmt.Sprintf("type=bind,source=%s,target=/workspace", workspacePath),
		"--tmpfs", "/tmp:rw,exec,nosuid,nodev",
		"--network", "none",
		"--read-only",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
	}
	if e.collectPolicy.MemoryLimitMB > 0 {
		args = append(args,
			"--memory", fmt.Sprintf("%dm", e.collectPolicy.MemoryLimitMB),
			"--memory-swap", fmt.Sprintf("%dm", e.collectPolicy.MemoryLimitMB*2),
		)
	}
	if e.collectPolicy.CPULimitPercent > 0 {
		args = append(args,
			"--cpu-period", "100000",
			"--cpu-quota", fmt.Sprintf("%d", e.collectPolicy.CPULimitPercent*1000),
		)
	}
	if e.collectPolicy.ProcessLimit > 0 {
		args = append(args, "--pids-limit", fmt.Sprintf("%d", e.collectPolicy.ProcessLimit))
	}
	args = append(args, "--ulimit", "nofile=1024:1024")
	for _, pair := range env {
		args = append(args, "--env", pair)
	}
	// The image terminates the option list; everything after it is the command.
	return append(args, e.collectPolicy.Image)
}

// cleanupContainer force-removes a container. It deliberately ignores parent
// cancellation so cleanup still runs after the caller's context is done.
func (e *DockerExecutor) cleanupContainer(ctx context.Context, name string) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cleanupCtx, "docker", "rm", "-f", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CollectPolicy defines collection constraints.
type CollectPolicy struct {
	// Image is the container image used for execution. It is required: without
	// it `docker run` would treat the command as the image name.
	Image           string
	MaxOutput       int
	Timeout         time.Duration
	MemoryLimitMB   int
	CPULimitPercent int
	ProcessLimit    int
}

// Validate validates a collect request against the policy.
func (p CollectPolicy) Validate(command []string, dir string, env []string, maxOut int, timeout time.Duration) error {
	//Validate command
	if len(command) == 0 {
		return fmt.Errorf("command is required")
	}
	if !allowedCommand(command[0]) {
		return fmt.Errorf("command %q not allowed", command[0])
	}
	//Validate image
	if p.Image == "" {
		return fmt.Errorf("container image is required")
	}
	if strings.HasPrefix(p.Image, "-") || strings.ContainsAny(p.Image, " \t\n") {
		return fmt.Errorf("invalid container image %q", p.Image)
	}
	//Validate directory
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("directory %q must be absolute", dir)
	}
	//Validate environment
	for _, pair := range env {
		parts := strings.SplitN(pair, "=", 2)
		if !allowedEnvVar(parts[0]) {
			return fmt.Errorf("environment variable %q not allowed", parts[0])
		}
	}
	//Validate timeout
	if timeout > p.Timeout {
		return fmt.Errorf("timeout %v exceeds policy timeout %v", timeout, p.Timeout)
	}
	//Validate max output
	if maxOut > p.MaxOutput {
		return fmt.Errorf("output limit %d exceeds policy max %d", maxOut, p.MaxOutput)
	}
	//Validate memory
	if p.MemoryLimitMB > 0 && p.MemoryLimitMB < 100 {
		return fmt.Errorf("memory limit %d MB too small", p.MemoryLimitMB)
	}
	//Validate CPU
	if p.CPULimitPercent > 0 && p.CPULimitPercent > 100 {
		return fmt.Errorf("CPU limit %d%% too high", p.CPULimitPercent)
	}
	//Validate process limit
	if p.ProcessLimit > 0 && p.ProcessLimit < 10 {
		return fmt.Errorf("process limit %d too small", p.ProcessLimit)
	}
	return nil
}

// allowedCommand checks if a command is allowed.
func allowedCommand(cmd string) bool {
	allowed := []string{"make", "go", "cargo", "npm", "yarn", "python", "python3"}
	for _, a := range allowed {
		if cmd == a {
			return true
		}
	}
	return false
}

// allowedEnvVar checks if an environment variable is allowed.
func allowedEnvVar(envVar string) bool {
	allowed := []string{"PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "COLORTERM"}
	for _, a := range allowed {
		if envVar == a {
			return true
		}
	}
	return false
}
