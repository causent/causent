package domain

import (
	"fmt"
	"time"
)

// Investigation represents a debugging investigation.
type Investigation struct {
	ID          ID
	RepoPath    string
	Command     []string
	Status      Status
	CreatedAt   time.Time
	UpdatedAt   time.Time
	BudgetSteps int
	BudgetUsed  int
}

// Reproduction represents the result of attempting to reproduce a failure.
type Reproduction struct {
	InvestigationID ID
	Result          *ExecutionResult
	Reproducible    bool
	Reason          string
}

// Evidence represents a piece of evidence collected during an investigation.
type Evidence struct {
	ID                 ID
	InvestigationID    ID
	Type               EvidenceType
	Source             string
	Timestamp          time.Time
	ContentRef         string
	Digest             string
	Payload            string
	ArtifactID         ID
	RelatedHypotheses  []ID
	RelatedExperiments []ID
	Provenance         string
}

// EvidenceType enumerates the types of evidence.
type EvidenceType string

const (
	EvidenceReproduction    EvidenceType = "reproduction"
	EvidenceGitDiff         EvidenceType = "git_diff"
	EvidenceSourceCode      EvidenceType = "source_code"
	EvidenceStackTrace      EvidenceType = "stack_trace"
	EvidenceBaselineCompare EvidenceType = "baseline_compare"
)

// Hypothesis represents a hypothesis about the cause of a failure.
type Hypothesis struct {
	ID                       ID
	InvestigationID          ID
	Statement                string
	AffectedComponent        string
	SupportingEvidenceIDs    []ID
	ContradictingEvidenceIDs []ID
	PredictedObservations    []string
	Confidence               float64
	Status                   HypothesisStatus
	CreatedAt                time.Time
	UpdatedAt                time.Time
	ExperimentIDs            []ID
	Provenance               string
}

// HypothesisStatus enumerates the status of a hypothesis.
type HypothesisStatus string

const (
	HypProposed           HypothesisStatus = "proposed"
	HypUnderInvestigation HypothesisStatus = "under_investigation"
	HypSupported          HypothesisStatus = "supported"
	HypRefuted            HypothesisStatus = "refuted"
	HypInconclusive       HypothesisStatus = "inconclusive"
)

// Experiment represents an experiment run during an investigation.
type Experiment struct {
	ID                      ID
	InvestigationID         ID
	Type                    ExperimentType
	Purpose                 ExperimentPurpose
	HypothesesIDs           []ID
	Command                 []string
	WorkingDir              string
	ExpectedUnderHypothesis map[ID]string
	Timeout                 time.Duration
	MaxOutput               int
	Status                  Status
	Outcome                 ExperimentOutcome
	Result                  *ExecutionResult
	EvidenceProduced        []ID
	CreatedAt               time.Time
	StartedAt               *time.Time
	FinishedAt              *time.Time
	Error                   string
	State                   ExperimentState
	Description             string
	Predictions             map[ID]string
	Observations            string
	Evaluation              string
	SelectionReason         string
	RequiredPermissions     []string
}

type ExperimentState string

const (
	ExperimentPlanned      ExperimentState = "planned"
	ExperimentApproved     ExperimentState = "approved"
	ExperimentRunning      ExperimentState = "running"
	ExperimentCompleted    ExperimentState = "completed"
	ExperimentFailed       ExperimentState = "failed"
	ExperimentCancelled    ExperimentState = "cancelled"
	ExperimentInconclusive ExperimentState = "inconclusive"
)

func ValidateExperimentTransition(from, to ExperimentState) error {
	if from == to {
		return nil
	}
	allowed := map[ExperimentState][]ExperimentState{
		"":                     {ExperimentPlanned},
		ExperimentPlanned:      {ExperimentApproved, ExperimentCancelled},
		ExperimentApproved:     {ExperimentRunning, ExperimentCancelled},
		ExperimentRunning:      {ExperimentCompleted, ExperimentFailed, ExperimentCancelled, ExperimentInconclusive},
		ExperimentCompleted:    {},
		ExperimentFailed:       {},
		ExperimentCancelled:    {},
		ExperimentInconclusive: {},
	}
	for _, candidate := range allowed[from] {
		if candidate == to {
			return nil
		}
	}
	return fmt.Errorf("invalid experiment transition: %s -> %s", from, to)
}

type HypothesisHistory struct {
	ID                 ID
	HypothesisID       ID
	InvestigationID    ID
	PreviousStatus     HypothesisStatus
	NextStatus         HypothesisStatus
	PreviousConfidence float64
	NextConfidence     float64
	ExperimentID       ID
	Evaluation         string
	CreatedAt          time.Time
}

// ExperimentType enumerates the types of experiments.
type ExperimentType string

const (
	ExpDeterministicDiagnostic ExperimentType = "deterministic_diagnostic"
	ExpRunFocusedTest          ExperimentType = "run_focused_test"
	ExpRunReproduction         ExperimentType = "run_reproduction"
)

// ExperimentPurpose enumerates the purposes of experiments.
type ExperimentPurpose string

const (
	PurposeDistinguish    ExperimentPurpose = "distinguish"
	PurposeTestPrediction ExperimentPurpose = "test_prediction"
	PurposeGatherEvidence ExperimentPurpose = "gather_evidence"
)

// ExperimentOutcome enumerates the outcomes of experiments.
type ExperimentOutcome string

const (
	OutcomeSupports     ExperimentOutcome = "supports"
	OutcomeContradicts  ExperimentOutcome = "contradicts"
	OutcomeInconclusive ExperimentOutcome = "inconclusive"
	OutcomeFailed       ExperimentOutcome = "failed"
)

// Patch represents a proposed fix generated during an investigation.
type Patch struct {
	ID                 ID
	InvestigationID    ID
	Diff               string
	DiffPath           string
	WorkspacePath      string
	Status             PatchStatus
	OriginalTestResult *ExecutionResult
	RegressionResults  []ExecutionResult
	CreatedAt          time.Time
	VerifiedAt         *time.Time
	Error              string
	HypothesisIDs      []ID
	Explanation        string
	ExpectedBehavior   string
	ChangedFiles       []string
	Digest             string
	BaseRevision       string
	Provider           ModelMetadata
	ValidationStatus   string
	ApplicationStatus  string
	VerificationStatus string
	VerificationReport string
}

type VerificationStatus string

const (
	VerificationPassed       VerificationStatus = "passed"
	VerificationFailed       VerificationStatus = "failed"
	VerificationInconclusive VerificationStatus = "inconclusive"
	VerificationError        VerificationStatus = "error"
	VerificationCancelled    VerificationStatus = "cancelled"
)

type PatchProposal struct {
	HypothesisIDs    []ID           `json:"hypothesis_ids"`
	Explanation      string         `json:"explanation"`
	ExpectedBehavior string         `json:"expected_behavior"`
	ChangedFiles     []string       `json:"changed_files"`
	Diff             string         `json:"unified_diff"`
	Edits            []EditProposal `json:"edits"`
	Risks            []string       `json:"risks"`
	Metadata         ModelMetadata  `json:"metadata"`
}

type EditProposal struct {
	File    string `json:"file"`
	OldText string `json:"old_text"`
	NewText string `json:"new_text"`
}

type VerificationReport struct {
	PatchID              ID
	Status               VerificationStatus
	BaseRevision         string
	ApplicationError     string
	Baseline             *ExecutionResult
	OriginalAfterPatch   *ExecutionResult
	RegressionResults    []ExecutionResult
	TestsNotExecuted     []string
	EvidenceIDs          []ID
	OriginalResolved     bool
	RegressionsPassed    bool
	RootCauseVerified    bool
	RemainingUncertainty []string
	CreatedAt            time.Time
}

type PatchComparison struct {
	InvestigationID ID
	PatchIDs        []ID
	Ranked          []ID
	Reasons         map[ID][]string
	CreatedAt       time.Time
}

type EvaluationStrategy string

const (
	StrategyDirectRepair   EvaluationStrategy = "direct_repair"
	StrategyEvidenceGuided EvaluationStrategy = "evidence_guided"
	StrategyEvidenceOnly   EvaluationStrategy = "evidence_only"
	StrategyHypothesesOnly EvaluationStrategy = "hypotheses_only"
)

type EvaluationOutcome string

const (
	EvaluationSuccess        EvaluationOutcome = "success"
	EvaluationFailure        EvaluationOutcome = "failure"
	EvaluationTimeout        EvaluationOutcome = "timeout"
	EvaluationIncomplete     EvaluationOutcome = "incomplete"
	EvaluationInfrastructure EvaluationOutcome = "infrastructure_failure"
)

type BenchmarkCase struct {
	ID                   string
	SuiteID              string
	Version              string
	Repository           string
	RepoPath             string
	BuggyRevision        string
	KnownGoodRevision    string
	Description          string
	ReproductionCommand  []string
	ExpectedFailure      string
	RootCause            string
	ExpectedCorrection   string
	VerificationCommands [][]string
	HiddenTests          [][]string
	Category             string
	Difficulty           string
	License              string
	Provenance           string
}

type BenchmarkSuite struct {
	ID          string
	Version     string
	Description string
	Cases       []BenchmarkCase
}

type EvaluationTrial struct {
	ID                  ID
	EvaluationID        ID
	SuiteID             string
	SuiteVersion        string
	CaseID              string
	Strategy            EvaluationStrategy
	Model               ModelMetadata
	PromptVersion       string
	InvestigationID     ID
	BuggyRevision       string
	KnownGoodRevision   string
	BudgetSteps         int
	Timeout             time.Duration
	StartedAt           time.Time
	FinishedAt          *time.Time
	Outcome             EvaluationOutcome
	OriginalResolved    bool
	RegressionFree      bool
	RootCauseCorrect    bool
	HypothesisPrecision float64
	HypothesisRecall    float64
	EvidenceQuality     float64
	Experiments         int
	ModelCalls          int
	InputTokens         int
	OutputTokens        int
	ExecutionTime       time.Duration
	Error               string
	IncompleteStage     string
	PatchID             ID
}

type EvaluationSummary struct {
	EvaluationID      ID
	SuiteID           string
	SuiteVersion      string
	Trials            int
	Completed         int
	Successes         int
	OriginalResolved  int
	RegressionFree    int
	RootCauseCorrect  int
	MeanDuration      time.Duration
	MedianDuration    time.Duration
	MeanExperiments   float64
	MeanModelCalls    float64
	SuccessRate       float64
	RegressionRate    float64
	RootCauseAccuracy float64
	Warnings          []string
	ByStrategy        map[EvaluationStrategy]EvaluationSummary
	CreatedAt         time.Time
}

type StrategyComparison struct {
	Left               EvaluationStrategy
	Right              EvaluationStrategy
	LeftSuccessRate    float64
	RightSuccessRate   float64
	AbsoluteDifference float64
	RelativeDifference float64
	PairedTrials       int
	Warnings           []string
}

// PatchStatus enumerates the status of a patch.
type PatchStatus string

const (
	PatchDoesNotApply  PatchStatus = "does_not_apply"
	PatchValidated     PatchStatus = "validated"
	PatchFailsOriginal PatchStatus = "fails_original"
)

// InvestigationEvent represents an event in the investigation lifecycle.
type InvestigationEvent struct {
	ID              ID
	InvestigationID ID
	PreviousStatus  Status
	NextStatus      Status
	Timestamp       time.Time
	Trigger         string
	ExperimentID    ID
	EvidenceID      ID
	Error           string
}

// Status represents the status of an investigation or experiment.
type Status string

const (
	StatusCreated            Status = "created"
	StatusPreparing          Status = "preparing"
	StatusReproducing        Status = "reproducing"
	StatusCollectingEvidence Status = "collecting_evidence"
	StatusFormingHypotheses  Status = "forming_hypotheses"
	StatusPlanningExperiment Status = "planning_experiment"
	StatusRunningExperiment  Status = "running_experiment"
	StatusEvaluatingEvidence Status = "evaluating_evidence"
	StatusGeneratingPatch    Status = "generating_patch"
	StatusVerifyingPatch     Status = "verifying_patch"
	StatusCompleted          Status = "completed"
	StatusInconclusive       Status = "inconclusive"
	StatusReproFailed        Status = "repro_failed"
	StatusExecutionFailed    Status = "execution_failed"
	StatusBudgetExhausted    Status = "budget_exhausted"
	StatusCancelled          Status = "cancelled"
)

// ValidateTransition validates a status transition.
func ValidateTransition(from, to Status) error {
	validTransitions := map[Status][]Status{
		StatusCreated:            {StatusPreparing},
		StatusPreparing:          {StatusReproducing},
		StatusReproducing:        {StatusCollectingEvidence, StatusExecutionFailed, StatusReproFailed},
		StatusCollectingEvidence: {StatusFormingHypotheses, StatusExecutionFailed},
		StatusFormingHypotheses:  {StatusCompleted, StatusPlanningExperiment},
		StatusPlanningExperiment: {StatusRunningExperiment, StatusEvaluatingEvidence},
		StatusRunningExperiment:  {StatusEvaluatingEvidence},
		StatusEvaluatingEvidence: {StatusGeneratingPatch, StatusCompleted, StatusInconclusive},
		StatusGeneratingPatch:    {StatusVerifyingPatch},
		StatusVerifyingPatch:     {StatusCompleted, StatusInconclusive},
	}

	valid, ok := validTransitions[from]
	if !ok {
		return fmt.Errorf("unknown status: %s", from)
	}

	allowed := false
	for _, s := range valid {
		if s == to {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("invalid transition: %s -> %s", from, to)
	}

	return nil
}

// IsTerminal returns true if the status is a terminal status.
func IsTerminal(status Status) bool {
	terminal := map[Status]bool{
		StatusCompleted:       true,
		StatusInconclusive:    true,
		StatusReproFailed:     true,
		StatusExecutionFailed: true,
		StatusBudgetExhausted: true,
		StatusCancelled:       true,
	}
	return terminal[status]
}

// BudgetExceededError represents an error when the budget is exceeded.
type BudgetExceededError struct{}

func (e *BudgetExceededError) Error() string {
	return "budget exceeded"
}

// CancellationError represents an error when the investigation is cancelled.
type CancellationError struct{}

func (e *CancellationError) Error() string {
	return "investigation cancelled"
}

// ExecutionResult represents the result of executing a command.
type ExecutionResult struct {
	ExitCode   int
	Stdout     string
	Stderr     string
	Error      string
	TimedOut   bool
	Duration   time.Duration
	StartedAt  time.Time
	FinishedAt time.Time
}

// DiagnosisResult represents the result of an investigation.
type DiagnosisResult struct {
	InvestigationID ID
	Reproduction    *Reproduction
	EvidenceCount   int
	HypothesisCount int
	ExperimentCount int
	Patch           *Patch
	Status          Status
	FinalReport     string
	Limitations     []string
	Unresolved      []string
	CompletedAt     time.Time
	Model           ModelMetadata
}

// ModelMetadata records the provider and request configuration used to form
// hypotheses. It is intentionally separate from evidence: model output is
// analysis, never an observation.
type ModelMetadata struct {
	Provider  string
	Model     string
	Endpoint  string
	RequestID string
}

// Artifact represents stored execution artifacts (logs, traces, outputs).
type Artifact struct {
	ID              ID
	InvestigationID ID
	Type            string
	Path            string
	Size            int64
	Digest          string
	CreatedAt       time.Time
}
