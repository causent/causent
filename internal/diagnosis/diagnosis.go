// Package diagnosis implements Cypher's default, evidence-first workflow: it
// reproduces a failure, classifies it, localizes the change that introduced it,
// and emits a replayable bundle. It deliberately does not generate or apply
// patches; that remains the explicit opt-in repair workflow.
package diagnosis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Yashbhu/Hades/internal/agent"
	"github.com/Yashbhu/Hades/internal/domain"
	"github.com/Yashbhu/Hades/internal/execution"
	"github.com/Yashbhu/Hades/internal/persistence"
)

// Classification is the deterministic category assigned to an observed failure.
type Classification string

const (
	ClassRealRegression  Classification = "real_regression"
	ClassFlaky           Classification = "flaky"
	ClassDependencyDrift Classification = "dependency_or_toolchain_drift"
	ClassInfrastructure  Classification = "infrastructure_or_environment"
	ClassNotReproduced   Classification = "not_reproduced"
	ClassPreExisting     Classification = "pre_existing_failure"
)

// Event names emitted to the event store and to events.jsonl.
const (
	EventDiagnosisStarted       = "diagnosis_started"
	EventReproductionStarted    = "reproduction_started"
	EventReproductionCompleted  = "reproduction_completed"
	EventClassificationComplete = "classification_completed"
	EventLocalizationStarted    = "localization_started"
	EventLocalizationCompleted  = "localization_completed"
	EventBundleCreated          = "bundle_created"
	EventDiagnosisCompleted     = "diagnosis_completed"
	EventDiagnosisRefused       = "diagnosis_refused"
)

// Defaults bound every loop in this package.
const (
	DefaultAttempts    = 3
	DefaultTimeout     = 2 * time.Minute
	DefaultMaxCommits  = 20
	MaxEvidenceExcerpt = 4096
	MaxListedFiles     = 50
	RefusalConfidence  = 0.4
)

// Attempt is one reproduction run. It is an observation, never an inference.
type Attempt struct {
	Index        int           `json:"index"`
	ExitCode     int           `json:"exit_code"`
	TimedOut     bool          `json:"timed_out"`
	Executed     bool          `json:"executed"`
	Duration     time.Duration `json:"duration"`
	StdoutDigest string        `json:"stdout_digest"`
	StderrDigest string        `json:"stderr_digest"`
	Stderr       string        `json:"stderr_excerpt,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// Failed reports whether this attempt observed the failing behaviour.
func (a Attempt) Failed() bool {
	return a.Executed && !a.TimedOut && a.ExitCode != 0
}

// Passed reports whether this attempt observed a clean run.
func (a Attempt) Passed() bool {
	return a.Executed && !a.TimedOut && a.ExitCode == 0
}

// EvidenceItem is a fact recorded during the diagnosis. Hypotheses reference
// these by ID; they never replace them.
type EvidenceItem struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Digest string `json:"digest"`
	Detail string `json:"detail"`
}

// Claim is a hypothesis. It must cite evidence and carries its own confidence.
type Claim struct {
	ID            string   `json:"id"`
	Statement     string   `json:"statement"`
	Confidence    float64  `json:"confidence"`
	Supporting    []string `json:"supporting_evidence"`
	Contradicting []string `json:"contradicting_evidence,omitempty"`
}

// Probe is an optional diagnostic command. It is always labelled as a probe and
// is never presented as a fix or as verification of a fix.
type Probe struct {
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output_excerpt"`
	Note     string `json:"note"`
}

// CommitInfo is a bounded commit description used in localization.
type CommitInfo struct {
	SHA     string `json:"sha"`
	Subject string `json:"subject"`
}

// Localization records where the failure most likely entered the history.
type Localization struct {
	HeadCommit      string       `json:"head_commit"`
	LastKnownGood   string       `json:"last_known_good,omitempty"`
	FirstKnownBad   string       `json:"first_known_bad,omitempty"`
	BisectResult    string       `json:"bisect_result,omitempty"`
	BisectStatus    string       `json:"bisect_status"`
	BisectLog       string       `json:"bisect_log,omitempty"`
	LikelyFiles     []string     `json:"likely_files,omitempty"`
	LikelyFunctions []string     `json:"likely_functions,omitempty"`
	CandidateCommit []CommitInfo `json:"candidate_commits,omitempty"`
	CommitRange     string       `json:"commit_range,omitempty"`
}

// Environment is the bounded execution context. Secrets are never recorded.
type Environment struct {
	OS            string    `json:"os"`
	Arch          string    `json:"arch"`
	GoVersion     string    `json:"go_version,omitempty"`
	GitVersion    string    `json:"git_version,omitempty"`
	RepoPath      string    `json:"repo_path"`
	HeadCommit    string    `json:"head_commit"`
	DirtyWorktree bool      `json:"dirty_worktree"`
	Isolation     string    `json:"isolation"`
	Executor      string    `json:"executor,omitempty"`
	Image         string    `json:"image,omitempty"`
	RecordedAt    time.Time `json:"recorded_at"`
}

// Baseline is the recorded reproduction evidence.
type Baseline struct {
	Attempts   int       `json:"attempts"`
	Failures   int       `json:"failures"`
	Passes     int       `json:"passes"`
	TimedOut   int       `json:"timed_out"`
	Results    []Attempt `json:"results"`
	Command    []string  `json:"command"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

// Comparison records the counterfactual base-versus-head evidence.
type Comparison struct {
	BaseRef    string         `json:"base_ref"`
	BaseCommit string         `json:"base_commit"`
	HeadCommit string         `json:"head_commit"`
	Base       Baseline       `json:"base"`
	Head       Baseline       `json:"head"`
	Verdict    Classification `json:"verdict"`
}

// Report is the final diagnosis.
type Report struct {
	InvestigationID string         `json:"investigation_id"`
	RepoPath        string         `json:"repo_path"`
	Command         []string       `json:"command"`
	Classification  Classification `json:"classification"`
	Environment     Environment    `json:"environment"`
	Baseline        Baseline       `json:"baseline"`
	Comparison      *Comparison    `json:"comparison,omitempty"`
	Agent           *agent.Report  `json:"agent,omitempty"`
	Localization    Localization   `json:"localization"`
	Evidence        []EvidenceItem `json:"evidence"`
	Claims          []Claim        `json:"claims"`
	Confidence      float64        `json:"confidence"`
	Uncertainty     []string       `json:"uncertainty"`
	Refused         bool           `json:"refused"`
	RefusalReason   string         `json:"refusal_reason,omitempty"`
	Probes          []Probe        `json:"probes,omitempty"`
	BundlePath      string         `json:"bundle_path,omitempty"`
	ReplayCommand   string         `json:"replay_command,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
}

// Config controls one diagnosis run.
type Config struct {
	RepoPath string
	Command  []string
	Attempts int
	Timeout  time.Duration
	// Executor runs the command. It is required so local and container
	// execution stay interchangeable behind one interface.
	Executor      execution.Executor
	ExecutorName  string
	ExecutorImage string
	// Store is optional. When set, events are persisted and can be streamed by
	// the gateway over SSE.
	Store *persistence.Store
	// BundleDir is where the replayable bundle is written. When empty no bundle
	// is written.
	BundleDir string
	// GoodRef is an optional known-good revision. When set, localization uses
	// git bisect instead of walking back from HEAD.
	GoodRef    string
	BaseRef    string
	Agent      *agent.Client
	MaxCommits int
	Probes     [][]string
}

// Diagnoser executes the diagnosis workflow.
type Diagnoser struct {
	cfg             Config
	events          []EventRecord
	investigationID string
}

// EventRecord is one entry in events.jsonl and, when a store is configured, one
// row in the investigation event table.
type EventRecord struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"`
	Status    string    `json:"status"`
	Detail    string    `json:"detail,omitempty"`
}

// Run performs the full diagnosis workflow.
func Run(ctx context.Context, cfg Config) (Report, error) {
	if cfg.Attempts <= 0 {
		cfg.Attempts = DefaultAttempts
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.MaxCommits <= 0 {
		cfg.MaxCommits = DefaultMaxCommits
	}
	if cfg.Executor == nil {
		return Report{}, fmt.Errorf("executor is required")
	}
	if len(cfg.Command) == 0 {
		return Report{}, fmt.Errorf("command is required")
	}
	if _, err := os.Stat(cfg.RepoPath); err != nil {
		return Report{}, fmt.Errorf("repo path does not exist: %s", cfg.RepoPath)
	}

	d := &Diagnoser{cfg: cfg}
	report := Report{
		InvestigationID: newID(),
		RepoPath:        cfg.RepoPath,
		Command:         cfg.Command,
		CreatedAt:       time.Now().UTC(),
	}
	d.investigationID = report.InvestigationID

	// Create the investigation so the gateway can stream this run.
	if cfg.Store != nil {
		inv := domain.Investigation{
			ID:          domain.ID(report.InvestigationID),
			RepoPath:    cfg.RepoPath,
			Command:     cfg.Command,
			Status:      domain.StatusCreated,
			CreatedAt:   report.CreatedAt,
			UpdatedAt:   report.CreatedAt,
			BudgetSteps: cfg.MaxCommits,
		}
		if err := cfg.Store.SaveInvestigation(inv); err != nil {
			return report, fmt.Errorf("save investigation: %w", err)
		}
	}
	d.emit(EventDiagnosisStarted, domain.StatusPreparing, "diagnosis workflow started")

	d.emit(EventReproductionStarted, domain.StatusReproducing, "reproducing failure in isolated workspace")

	baseline, env, workspace, cleanup, err := d.reproduce(ctx)
	if err != nil {
		d.emit(EventDiagnosisRefused, domain.StatusInconclusive, err.Error())
		return report, err
	}
	defer cleanup()

	report.Baseline = baseline
	env.Executor = cfg.ExecutorName
	env.Image = cfg.ExecutorImage
	report.Environment = env
	report.Classification = Classify(baseline.Results)
	if cfg.BaseRef != "" {
		comparison, cmpErr := d.compare(ctx, cfg.BaseRef, baseline, env.HeadCommit)
		if cmpErr != nil {
			report.Uncertainty = append(report.Uncertainty, "base comparison incomplete: "+cmpErr.Error())
		} else {
			report.Comparison = &comparison
			report.Classification = comparison.Verdict
		}
	}
	d.emit(EventReproductionCompleted, domain.StatusCollectingEvidence,
		fmt.Sprintf("%d/%d attempts failed", baseline.Failures, baseline.Attempts))
	d.emit(EventClassificationComplete, domain.StatusCollectingEvidence, string(report.Classification))

	report.Evidence = append(report.Evidence, attemptEvidence(baseline)...)
	report.Evidence = append(report.Evidence, classificationEvidence(report.Classification, baseline))

	// Refuse before localization when the failure itself is not established.
	if reason, ok := refusalReason(report.Classification, baseline); ok {
		report.Refused = true
		report.RefusalReason = reason
		report.Localization = Localization{HeadCommit: env.HeadCommit, BisectStatus: "skipped: diagnosis refused"}
		report.Uncertainty = append(report.Uncertainty, reason)
		report.Confidence = 0
		finish(&report, d, workspace)
		return report, nil
	}
	if cfg.Agent != nil {
		input := agent.Input{Classification: string(report.Classification), Command: report.Command}
		for _, e := range report.Evidence {
			input.Evidence = append(input.Evidence, agent.Evidence{ID: e.ID, Kind: e.Kind, Detail: e.Detail})
		}
		if result, agentErr := cfg.Agent.Analyze(ctx, input); agentErr != nil {
			report.Uncertainty = append(report.Uncertainty, "agent analysis unavailable: "+agentErr.Error())
		} else {
			report.Agent = &result
		}
	}

	d.emit(EventLocalizationStarted, domain.StatusFormingHypotheses, "localizing likely cause")
	localization, locEvidence, locErr := d.localize(ctx, workspace, baseline)
	report.Localization = localization
	report.Evidence = append(report.Evidence, locEvidence...)
	if locErr != nil {
		report.Uncertainty = append(report.Uncertainty, "localization incomplete: "+locErr.Error())
	}
	d.emit(EventLocalizationCompleted, domain.StatusFormingHypotheses, locStatus(localization))

	report.Claims = buildClaims(report.Classification, localization, report.Evidence)
	if err := ValidateContract(report); err != nil {
		report.Uncertainty = append(report.Uncertainty, "diagnosis contract validation failed: "+err.Error())
		report.Refused = true
		report.RefusalReason = "generated diagnosis contained unsupported evidence references"
		report.Claims = nil
	}
	report.Confidence = confidence(report.Classification, localization, report.Uncertainty)
	report.Uncertainty = append(report.Uncertainty, defaultUncertainty(report.Classification, localization)...)

	if len(report.Evidence) == 0 {
		report.Refused = true
		report.RefusalReason = "no evidence was collected"
	} else if report.Confidence < RefusalConfidence {
		report.Refused = true
		report.RefusalReason = fmt.Sprintf("confidence %.2f is below the %.2f threshold; evidence is insufficient for a diagnosis", report.Confidence, RefusalConfidence)
	}

	if len(cfg.Probes) > 0 {
		report.Probes = d.runProbes(ctx, workspace)
	}

	finish(&report, d, workspace)
	return report, nil
}

func (d *Diagnoser) compare(ctx context.Context, baseRef string, head Baseline, headCommit string) (Comparison, error) {
	baseCommit := strings.TrimSpace(gitOutput(d.cfg.RepoPath, "rev-parse", baseRef))
	if baseCommit == "" {
		return Comparison{}, fmt.Errorf("base revision %q could not be resolved", baseRef)
	}
	base := Baseline{Attempts: d.cfg.Attempts, Command: d.cfg.Command, StartedAt: time.Now().UTC()}
	dir, cleanup, err := isolatedWorkspace(ctx, d.cfg.RepoPath, baseCommit)
	if err != nil {
		return Comparison{}, err
	}
	defer cleanup()
	for i := 0; i < d.cfg.Attempts; i++ {
		a := d.runOnce(ctx, dir, i)
		base.Results = append(base.Results, a)
		if a.Failed() {
			base.Failures++
		}
		if a.Passed() {
			base.Passes++
		}
		if a.TimedOut {
			base.TimedOut++
		}
	}
	base.FinishedAt = time.Now().UTC()
	return Comparison{BaseRef: baseRef, BaseCommit: baseCommit, HeadCommit: headCommit, Base: base, Head: head, Verdict: compareVerdict(base, head)}, nil
}

func compareVerdict(base, head Baseline) Classification {
	if (base.Failures > 0 && base.Passes > 0) || (head.Failures > 0 && head.Passes > 0) {
		return ClassFlaky
	}
	if base.Failures > 0 || head.Failures > 0 {
		if base.Passes > 0 && head.Failures > 0 && head.Passes == 0 {
			return ClassRealRegression
		}
		if base.Failures > 0 && head.Failures > 0 {
			return ClassPreExisting
		}
		if base.Passes > 0 && head.Passes > 0 {
			return ClassNotReproduced
		}
		return ClassFlaky
	}
	return ClassNotReproduced
}

// finish writes the bundle, emits the terminal events, and persists the final
// investigation status.
func finish(report *Report, d *Diagnoser, workspace string) {
	if d.cfg.BundleDir != "" {
		path, err := WriteBundle(*report, d.events, d.cfg.BundleDir)
		if err != nil {
			report.Uncertainty = append(report.Uncertainty, "bundle could not be written: "+err.Error())
			d.emit(EventBundleCreated, statusFor(*report), "bundle failed: "+err.Error())
		} else {
			report.BundlePath = path
			report.ReplayCommand = fmt.Sprintf("cypher replay %s", path)
			d.emit(EventBundleCreated, statusFor(*report), path)
		}
	}
	if report.Refused {
		d.emit(EventDiagnosisRefused, domain.StatusInconclusive, report.RefusalReason)
	} else {
		d.emit(EventDiagnosisCompleted, domain.StatusCompleted, string(report.Classification))
	}
	// Refresh the bundle so events.jsonl and the manifest include the terminal
	// events emitted above, while keeping the reported path stable.
	if report.BundlePath != "" {
		if _, err := WriteBundle(*report, d.events, report.BundlePath); err != nil {
			report.Uncertainty = append(report.Uncertainty, "bundle refresh failed: "+err.Error())
		}
	}
	_ = workspace
}

func statusFor(report Report) domain.Status {
	if report.Refused {
		return domain.StatusInconclusive
	}
	return domain.StatusCompleted
}

// reproduce runs the command Attempts times in an isolated workspace.
func (d *Diagnoser) reproduce(ctx context.Context) (Baseline, Environment, string, func(), error) {
	env := captureEnvironment(d.cfg.RepoPath)
	workspace, cleanup, err := isolatedWorkspace(ctx, d.cfg.RepoPath, env.HeadCommit)
	if err != nil {
		return Baseline{}, env, "", func() {}, fmt.Errorf("create isolated workspace: %w", err)
	}
	env.Isolation = "git worktree at " + env.HeadCommit

	baseline := Baseline{
		Attempts:  d.cfg.Attempts,
		Command:   d.cfg.Command,
		StartedAt: time.Now().UTC(),
	}
	for i := 0; i < d.cfg.Attempts; i++ {
		if ctx.Err() != nil {
			cleanup()
			return baseline, env, "", func() {}, ctx.Err()
		}
		attempt := d.runOnce(ctx, workspace, i)
		baseline.Results = append(baseline.Results, attempt)
		switch {
		case attempt.Failed():
			baseline.Failures++
		case attempt.Passed():
			baseline.Passes++
		}
		if attempt.TimedOut {
			baseline.TimedOut++
		}
	}
	baseline.FinishedAt = time.Now().UTC()
	// Keep the commit identifier canonical. git's combined output includes a
	// trailing newline, and recording it verbatim makes replay treat the
	// revision as invalid (for example, "<sha>\n^{commit}").
	env.HeadCommit = strings.TrimSpace(gitOutput(d.cfg.RepoPath, "rev-parse", "HEAD"))
	return baseline, env, workspace, cleanup, nil
}

func (d *Diagnoser) runOnce(ctx context.Context, dir string, index int) Attempt {
	runCtx, cancel := context.WithTimeout(ctx, d.cfg.Timeout)
	defer cancel()
	res, err := d.cfg.Executor.Run(runCtx, execution.Request{
		Command:   d.cfg.Command,
		Dir:       dir,
		Timeout:   d.cfg.Timeout,
		MaxOutput: 64 << 10,
	})
	attempt := Attempt{
		Index:        index,
		ExitCode:     res.ExitCode,
		TimedOut:     res.TimedOut,
		Executed:     res.StartedAt != (time.Time{}) || res.TimedOut,
		Duration:     res.Duration,
		StdoutDigest: digestString(res.Stdout),
		StderrDigest: digestString(res.Stderr),
		Stderr:       bound(res.Stderr+"\n"+res.Stdout, MaxEvidenceExcerpt),
	}
	if err != nil {
		attempt.Error = err.Error()
		if !attempt.TimedOut {
			attempt.Executed = res.StartedAt != (time.Time{})
		}
	}
	return attempt
}

func (d *Diagnoser) runProbes(ctx context.Context, workspace string) []Probe {
	var probes []Probe
	for _, command := range d.cfg.Probes {
		if len(command) == 0 || len(probes) >= 10 {
			continue
		}
		runCtx, cancel := context.WithTimeout(ctx, d.cfg.Timeout)
		res, err := d.cfg.Executor.Run(runCtx, execution.Request{
			Command:   command,
			Dir:       workspace,
			Timeout:   d.cfg.Timeout,
			MaxOutput: 32 << 10,
		})
		cancel()
		probe := Probe{
			Command:  strings.Join(command, " "),
			ExitCode: res.ExitCode,
			Output:   bound(res.Stdout+"\n"+res.Stderr, MaxEvidenceExcerpt),
			Note:     "diagnostic probe; not a fix and not verification of a fix",
		}
		if err != nil && probe.Output == "" {
			probe.Output = err.Error()
		}
		probes = append(probes, probe)
	}
	return probes
}

// emit records an event locally and, when configured, in the investigation store
// so the gateway can stream it. Events are written with the real event ID.
func (d *Diagnoser) emit(name string, status domain.Status, detail string) {
	record := EventRecord{
		ID:        newID(),
		Timestamp: time.Now().UTC(),
		Event:     name,
		Status:    string(status),
		Detail:    detail,
	}
	d.events = append(d.events, record)
	if d.cfg.Store == nil {
		return
	}
	_ = d.cfg.Store.SaveEvent(domain.InvestigationEvent{
		ID:              domain.ID(record.ID),
		InvestigationID: domain.ID(d.investigationID),
		PreviousStatus:  status,
		NextStatus:      status,
		Timestamp:       record.Timestamp,
		Trigger:         name,
		Error:           "",
	})
}

func newID() string {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	return time.Now().UTC().Format("20060102T150405.000000000") + "-" + hex.EncodeToString(buf)
}

func digestString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func bound(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "\n... [truncated]"
}

func locStatus(l Localization) string {
	if l.BisectResult != "" {
		return "first bad commit " + l.BisectResult
	}
	if l.FirstKnownBad != "" {
		return "first bad commit " + l.FirstKnownBad
	}
	return "no localization found"
}
