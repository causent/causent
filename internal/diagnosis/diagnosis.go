// Package diagnosis implements Malenia's default, evidence-first workflow: it
// reproduces a failure, classifies it, localizes the change that introduced it,
// and emits a replayable bundle. It deliberately does not generate or apply
// patches; that remains the explicit opt-in repair workflow.
package diagnosis

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/causent/malenia/internal/agent"
	"github.com/causent/malenia/internal/domain"
	"github.com/causent/malenia/internal/execution"
	"github.com/causent/malenia/internal/observability"
	"github.com/causent/malenia/internal/persistence"
	programrepo "github.com/causent/malenia/internal/repository"
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
	EventPreliminaryDiagnosis   = "preliminary_diagnosis"
)

// Defaults bound every loop in this package.
const (
	DefaultAttempts              = 3
	DefaultTimeout               = 2 * time.Minute
	DefaultMaxCommits            = 20
	DefaultMaxLocalizationProbes = 6
	MaxEvidenceExcerpt           = 4096
	MaxListedFiles               = 50
	RefusalConfidence            = 0.4
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
	InvestigationID     string                         `json:"investigation_id"`
	RepoPath            string                         `json:"repo_path"`
	Command             []string                       `json:"command"`
	Classification      Classification                 `json:"classification"`
	Environment         Environment                    `json:"environment"`
	Baseline            Baseline                       `json:"baseline"`
	Comparison          *Comparison                    `json:"comparison,omitempty"`
	Agent               *agent.Report                  `json:"agent,omitempty"`
	AgentStatus         string                         `json:"agent_status"`
	AgentError          string                         `json:"agent_error,omitempty"`
	Localization        Localization                   `json:"localization"`
	Evidence            []EvidenceItem                 `json:"evidence"`
	Candidates          []domain.CandidateLocation     `json:"candidates,omitempty"`
	Relationships       []domain.Relationship          `json:"relationships,omitempty"`
	FailureGroups       []domain.FailureGroup          `json:"failure_groups,omitempty"`
	FailureEpisodes     []domain.FailureEpisode        `json:"failure_episodes,omitempty"`
	Hypotheses          []domain.Hypothesis            `json:"hypotheses,omitempty"`
	Findings            []domain.DiagnosticFinding     `json:"findings,omitempty"`
	Preliminary         *domain.DiagnosticFinding      `json:"preliminary,omitempty"`
	Overview            *programrepo.Overview          `json:"overview,omitempty"`
	Metrics             *observability.Metrics         `json:"metrics,omitempty"`
	IndexingMode        string                         `json:"indexing_mode,omitempty"`
	CoverageNotes       []string                       `json:"coverage_notes,omitempty"`
	Partial             bool                           `json:"partial,omitempty"`
	Experiments         []domain.Experiment            `json:"experiments,omitempty"`
	UnresolvedQuestions []domain.InvestigationQuestion `json:"unresolved_questions,omitempty"`
	StoppingReason      string                         `json:"stopping_reason,omitempty"`
	AdaptiveIterations  int                            `json:"adaptive_iterations,omitempty"`
	HistoricalContext   []domain.HistoricalReference   `json:"historical_context,omitempty"`
	Claims              []Claim                        `json:"claims"`
	Confidence          float64                        `json:"confidence"`
	Uncertainty         []string                       `json:"uncertainty"`
	Refused             bool                           `json:"refused"`
	RefusalReason       string                         `json:"refusal_reason,omitempty"`
	Probes              []Probe                        `json:"probes,omitempty"`
	BundlePath          string                         `json:"bundle_path,omitempty"`
	ReplayCommand       string                         `json:"replay_command,omitempty"`
	CreatedAt           time.Time                      `json:"created_at"`
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
	// MaxLocalizationProbes bounds test executions used to locate a revision boundary.
	MaxLocalizationProbes int
	Probes                [][]string
	// ExternalEvidence is bounded evidence collected by an integration such as
	// GitHub Actions. It is recorded separately from reproduction output.
	ExternalEvidence []EvidenceItem
	// Adaptive budgets bound the durable investigation loop. Zero values use
	// conservative defaults and never permit unbounded action execution.
	InvestigationID        string
	AdaptiveMaxIterations  int
	AdaptiveMaxActivities  int
	AdaptiveMaxExperiments int
	AdaptiveTimeout        time.Duration
	// InvestigationTimeout bounds the whole diagnosis, separately from per-command Timeout.
	InvestigationTimeout time.Duration
	// CacheDir stores revision-aware repository artifacts. Empty uses <repo>/.malenia/artifact-cache.
	CacheDir string
	// SkipAdaptive disables Stage 4 deep investigation after the preliminary report.
	SkipAdaptive bool
}

// Diagnoser executes the diagnosis workflow.
type Diagnoser struct {
	cfg             Config
	events          []EventRecord
	investigationID string
	metrics         *observability.Metrics
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
	if cfg.MaxLocalizationProbes <= 0 {
		cfg.MaxLocalizationProbes = DefaultMaxLocalizationProbes
	}
	if cfg.AdaptiveMaxIterations <= 0 {
		cfg.AdaptiveMaxIterations = 4
	}
	if cfg.AdaptiveMaxActivities <= 0 {
		cfg.AdaptiveMaxActivities = 4
	}
	if cfg.AdaptiveMaxExperiments <= 0 {
		cfg.AdaptiveMaxExperiments = 2
	}
	if cfg.AdaptiveTimeout <= 0 {
		cfg.AdaptiveTimeout = cfg.Timeout
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
		InvestigationID: cfg.InvestigationID,
		RepoPath:        cfg.RepoPath,
		Command:         cfg.Command,
		CreatedAt:       time.Now().UTC(),
		AgentStatus:     "disabled",
	}
	if report.InvestigationID == "" {
		report.InvestigationID = newID()
	}
	report.Evidence = append(report.Evidence, cfg.ExternalEvidence...)
	d.investigationID = report.InvestigationID
	d.metrics = observability.NewMetrics(report.InvestigationID)

	if cfg.InvestigationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.InvestigationTimeout)
		defer cancel()
	}

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

	var workspace string
	var cleanup func()
	defer func() {
		if cleanup != nil {
			cleanup()
		}
		// Always persist terminal status and collected evidence, including after
		// cancellation or timeout. Optional stages must not erase partial results.
		finish(&report, d, workspace)
	}()

	d.emit(EventReproductionStarted, domain.StatusReproducing, "reproducing failure in isolated workspace")
	reproStage := d.metrics.Begin(observability.StageReproduction)
	baseline, env, ws, wsCleanup, err := d.reproduce(ctx)
	workspace, cleanup = ws, wsCleanup
	// Preserve attempts collected before cancellation or timeout. They are
	// useful evidence even when reproduction cannot complete.
	report.Baseline = baseline
	report.Environment = env
	if err != nil {
		reproStage.Done("failed", err)
		report.Partial = true
		report.Uncertainty = append(report.Uncertainty, "reproduction incomplete: "+err.Error())
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			report.Refused = true
			report.RefusalReason = "investigation cancelled or timed out before reproduction completed"
			d.emit(EventDiagnosisRefused, domain.StatusInconclusive, report.RefusalReason)
			return report, err
		}
		d.emit(EventDiagnosisRefused, domain.StatusInconclusive, err.Error())
		return report, err
	}
	reproStage.Count("attempts", baseline.Attempts)
	reproStage.Count("failures", baseline.Failures)
	reproStage.Done("completed", nil)

	report.Baseline = baseline
	env.Executor = cfg.ExecutorName
	env.Image = cfg.ExecutorImage
	report.Environment = env
	report.Classification = Classify(baseline.Results)
	if cfg.BaseRef != "" {
		cmpStage := d.metrics.Begin(observability.StageBaseComparison)
		comparison, cmpErr := d.compare(ctx, cfg.BaseRef, baseline, env.HeadCommit)
		if cmpErr != nil {
			cmpStage.Done("inconclusive", cmpErr)
			report.Uncertainty = append(report.Uncertainty, "base comparison incomplete: "+cmpErr.Error())
			report.Partial = true
			if isTimeoutOrCancel(cmpErr) {
				report.Uncertainty = append(report.Uncertainty, "base comparison timed out or was cancelled; result is inconclusive, not negative evidence")
			}
		} else {
			report.Comparison = &comparison
			report.Classification = comparison.Verdict
			cmpStage.Done("completed", nil)
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
		if err := d.persistArchitecture(ctx, &report, workspace, baseline, env, report.Localization); err != nil {
			report.Uncertainty = append(report.Uncertainty, "architecture persistence incomplete: "+err.Error())
			report.Partial = true
		}
		return report, nil
	}

	skipDeep := cfg.SkipAdaptive || reproductionInconclusive(baseline, report.Comparison)
	if skipDeep && !cfg.SkipAdaptive {
		report.Uncertainty = append(report.Uncertainty, "deep investigation skipped because reproduction or base comparison was inconclusive")
		report.Partial = true
	}

	d.emit(EventLocalizationStarted, domain.StatusFormingHypotheses, "localizing likely cause")
	locStage := d.metrics.Begin(observability.StageLocalization)
	localization, locEvidence, locErr := d.localize(ctx, workspace, baseline, report.Comparison)
	report.Localization = localization
	report.Evidence = append(report.Evidence, locEvidence...)
	if locErr != nil {
		locStage.Done("inconclusive", locErr)
		report.Uncertainty = append(report.Uncertainty, "localization incomplete: "+locErr.Error())
		report.Partial = true
		if isTimeoutOrCancel(locErr) {
			report.Uncertainty = append(report.Uncertainty, "localization timed out or was cancelled; collected evidence is preserved")
		}
	} else {
		locStage.Done("completed", nil)
	}
	if err := d.persistArchitecture(ctx, &report, workspace, baseline, env, localization); err != nil {
		report.Uncertainty = append(report.Uncertainty, "architecture persistence incomplete: "+err.Error())
		report.Partial = true
	}

	if !skipDeep && !cfg.SkipAdaptive {
		adaptStage := d.metrics.Begin(observability.StageAdaptiveDeep)
		if err := d.runAdaptiveLoop(ctx, &report, workspace); err != nil {
			adaptStage.Done("inconclusive", err)
			report.Uncertainty = append(report.Uncertainty, "adaptive investigation incomplete: "+err.Error())
			report.Partial = true
		} else {
			adaptStage.Count("actions", report.AdaptiveIterations)
			adaptStage.Count("experiments", len(report.Experiments))
			adaptStage.Done("completed", nil)
		}
	} else if report.StoppingReason == "" {
		report.StoppingReason = "adaptive investigation skipped"
	}
	d.emit(EventLocalizationCompleted, domain.StatusFormingHypotheses, locStatus(localization))

	report.Claims = buildClaims(report.Classification, localization, report.Evidence)
	if err := ValidateContract(report); err != nil {
		report.Uncertainty = append(report.Uncertainty, "diagnosis contract validation failed: "+err.Error())
		report.Refused = true
		report.RefusalReason = "generated diagnosis contained unsupported evidence references"
		report.Claims = nil
	}
	if cfg.Agent != nil {
		report.AgentStatus = "enabled"
		input := agent.Input{
			Classification: string(report.Classification),
			Command:        report.Command,
			Context: fmt.Sprintf("first_known_bad=%s\nlikely_files=%s\nclaims=%v",
				report.Localization.FirstKnownBad, strings.Join(report.Localization.LikelyFiles, ", "), report.Claims),
		}
		for _, e := range report.Evidence {
			input.Evidence = append(input.Evidence, agent.Evidence{ID: e.ID, Kind: e.Kind, Detail: e.Detail})
		}
		if result, agentErr := cfg.Agent.Analyze(ctx, input); agentErr != nil {
			report.AgentStatus = "failed"
			report.AgentError = agentErr.Error()
		} else {
			report.AgentStatus = "completed"
			report.Agent = &result
		}
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

	if len(cfg.Probes) > 0 && ctx.Err() == nil {
		report.Probes = d.runProbes(ctx, workspace)
	}

	return report, nil
}

func isTimeoutOrCancel(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func reproductionInconclusive(baseline Baseline, comparison *Comparison) bool {
	if baseline.TimedOut > 0 && baseline.Failures == 0 && baseline.Passes == 0 {
		return true
	}
	if comparison == nil {
		return false
	}
	if comparison.Base.TimedOut > 0 && comparison.Base.Failures == 0 && comparison.Base.Passes == 0 {
		return true
	}
	if comparison.Head.TimedOut > 0 && comparison.Head.Failures == 0 && comparison.Head.Passes == 0 {
		return true
	}
	return false
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
// investigation status. It is safe to call after cancellation: already collected
// evidence and preliminary findings are preserved.
func finish(report *Report, d *Diagnoser, workspace string) {
	var bundleStage *observability.StageHandle
	if d.metrics != nil {
		bundleStage = d.metrics.Begin(observability.StageBundlePublish)
	}
	if d.cfg.Store != nil {
		if inv, err := d.cfg.Store.GetInvestigation(domain.ID(report.InvestigationID)); err == nil {
			inv.Status = statusFor(*report)
			inv.UpdatedAt = time.Now().UTC()
			inv.BudgetUsed = report.AdaptiveIterations
			_ = d.cfg.Store.SaveInvestigation(inv)
		}
	}
	if d.cfg.BundleDir != "" {
		if d.metrics != nil {
			clone := d.metrics.Clone()
			report.Metrics = &clone
		}
		path, err := WriteBundle(*report, d.events, d.cfg.BundleDir)
		if err != nil {
			report.Uncertainty = append(report.Uncertainty, "bundle could not be written: "+err.Error())
			d.emit(EventBundleCreated, statusFor(*report), "bundle failed: "+err.Error())
			if bundleStage != nil {
				bundleStage.Done("failed", err)
			}
		} else {
			report.BundlePath = path
			report.ReplayCommand = fmt.Sprintf("malenia replay %s", path)
			d.emit(EventBundleCreated, statusFor(*report), path)
			if bundleStage != nil {
				bundleStage.Done("completed", nil)
			}
		}
	} else if bundleStage != nil {
		bundleStage.Done("skipped", nil)
	}
	if report.Refused {
		d.emit(EventDiagnosisRefused, domain.StatusInconclusive, report.RefusalReason)
	} else {
		d.emit(EventDiagnosisCompleted, domain.StatusCompleted, string(report.Classification))
	}
	if d.metrics != nil {
		inconclusive := report.Refused || report.Classification == ClassNotReproduced || report.Partial
		d.metrics.Finish(report.Partial, inconclusive)
		clone := d.metrics.Clone()
		report.Metrics = &clone
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
	if report.Refused || report.Partial {
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
