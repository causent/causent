package domain

import "time"

// Repository and revision entities keep program knowledge scoped to a source
// snapshot. They deliberately do not reuse RepoPath as an identity.
type Repository struct {
	ID            string            `json:"id"`
	Provider      string            `json:"provider"`
	Owner         string            `json:"owner"`
	Name          string            `json:"name"`
	CanonicalID   string            `json:"canonical_id"`
	Configuration map[string]string `json:"configuration,omitempty"`
}

type Revision struct {
	ID               string    `json:"id"`
	RepositoryID     string    `json:"repository_id"`
	CommitSHA        string    `json:"commit_sha"`
	ParentRevisionID string    `json:"parent_revision_id,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

type PullRequest struct {
	ID             string            `json:"id"`
	RepositoryID   string            `json:"repository_id"`
	ExternalPRID   string            `json:"external_pr_id"`
	BaseRevisionID string            `json:"base_revision_id"`
	HeadRevisionID string            `json:"head_revision_id"`
	Status         string            `json:"status"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

type CIExecution struct {
	ID                  string            `json:"id"`
	RepositoryID        string            `json:"repository_id"`
	PullRequestID       string            `json:"pull_request_id,omitempty"`
	BaseRevisionID      string            `json:"base_revision_id,omitempty"`
	HeadRevisionID      string            `json:"head_revision_id"`
	Provider            string            `json:"provider"`
	ExternalExecutionID string            `json:"external_execution_id"`
	Status              string            `json:"status"`
	StartedAt           *time.Time        `json:"started_at,omitempty"`
	CompletedAt         *time.Time        `json:"completed_at,omitempty"`
	ArtifactIDs         []ID              `json:"artifact_ids,omitempty"`
	RawMetadata         map[string]string `json:"raw_metadata,omitempty"`
}

type FailureEpisode struct {
	ID                     string `json:"id"`
	ExecutionID            string `json:"execution_id"`
	TestIdentifier         string `json:"test_identifier,omitempty"`
	TestFramework          string `json:"test_framework,omitempty"`
	FailureType            string `json:"failure_type,omitempty"`
	FailureMessage         string `json:"failure_message"`
	StackTraceEvidenceID   ID     `json:"stack_trace_evidence_id,omitempty"`
	ObservationEvidenceIDs []ID   `json:"observation_evidence_ids,omitempty"`
	Status                 string `json:"status"`
}

type CodeLocation struct {
	ID             string `json:"id"`
	RepositoryID   string `json:"repository_id"`
	RevisionID     string `json:"revision_id"`
	FilePath       string `json:"file_path"`
	SymbolIdentity string `json:"symbol_identity,omitempty"`
	StartLine      int    `json:"start_line,omitempty"`
	EndLine        int    `json:"end_line,omitempty"`
	LocationType   string `json:"location_type"`
	Provenance     string `json:"provenance,omitempty"`
}

// ProgramNode is a revision-scoped node in the repository/program graph.
// Identity is language-aware and never consists of a path alone.
type ProgramNode struct {
	ID            string `json:"id"`
	RepositoryID  string `json:"repository_id"`
	RevisionID    string `json:"revision_id"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Identity      string `json:"identity"`
	FilePath      string `json:"file_path,omitempty"`
	Language      string `json:"language,omitempty"`
	StartLine     int    `json:"start_line,omitempty"`
	EndLine       int    `json:"end_line,omitempty"`
	ContentDigest string `json:"content_digest,omitempty"`
	Changed       bool   `json:"changed"`
}

// CodeDelta describes a revision-scoped change that can be connected to a
// failure candidate. It is an observed base/head difference, not a causal
// conclusion by itself.
type CodeDelta struct {
	ID             string `json:"id"`
	RepositoryID   string `json:"repository_id"`
	BaseRevisionID string `json:"base_revision_id"`
	HeadRevisionID string `json:"head_revision_id"`
	Kind           string `json:"kind"` // added, removed, modified
	SymbolIdentity string `json:"symbol_identity"`
	FilePath       string `json:"file_path"`
	BaseStartLine  int    `json:"base_start_line,omitempty"`
	HeadStartLine  int    `json:"head_start_line,omitempty"`
	EvidenceID     ID     `json:"evidence_id,omitempty"`
	Summary        string `json:"summary"`
}

// ExecutionPath is a bounded, revision-scoped path through the repository
// graph connecting an observed failure to a candidate implementation.
type ExecutionPath struct {
	ID              string         `json:"id"`
	InvestigationID ID             `json:"investigation_id"`
	FailureIDs      []string       `json:"failure_ids,omitempty"`
	NodeIDs         []string       `json:"node_ids"`
	RelationshipIDs []string       `json:"relationship_ids"`
	Locations       []CodeLocation `json:"locations"`
	EvidenceIDs     []ID           `json:"evidence_ids,omitempty"`
	Status          string         `json:"status"`
	Summary         string         `json:"summary"`
}

type CandidateLocation struct {
	ID                       string       `json:"id"`
	InvestigationID          ID           `json:"investigation_id"`
	Location                 CodeLocation `json:"location"`
	Score                    ScoreVector  `json:"score"`
	SupportingEvidenceIDs    []ID         `json:"supporting_evidence_ids,omitempty"`
	ContradictingEvidenceIDs []ID         `json:"contradicting_evidence_ids,omitempty"`
	Status                   string       `json:"status"`
}

type ScoreVector struct {
	ExecutionRelevance   float64         `json:"execution_relevance"`
	ChangeRelevance      float64         `json:"change_relevance"`
	DependencyRelevance  float64         `json:"dependency_relevance"`
	BehaviouralRelevance float64         `json:"behavioural_relevance"`
	HistoricalRelevance  float64         `json:"historical_relevance"`
	RuntimeRelevance     float64         `json:"runtime_relevance"`
	AvailableDimensions  []string        `json:"available_dimensions"`
	EvidenceByDimension  map[string][]ID `json:"evidence_by_dimension,omitempty"`
	ScoringPolicyVersion string          `json:"scoring_policy_version"`
}

type Relationship struct {
	ID              string            `json:"id"`
	InvestigationID ID                `json:"investigation_id,omitempty"`
	SourceType      string            `json:"source_type"`
	SourceID        string            `json:"source_id"`
	TargetType      string            `json:"target_type"`
	TargetID        string            `json:"target_id"`
	Type            string            `json:"type"`
	RevisionID      string            `json:"revision_id,omitempty"`
	EvidenceIDs     []ID              `json:"evidence_ids,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
}

type DiagnosticFinding struct {
	ID              string    `json:"id"`
	InvestigationID ID        `json:"investigation_id"`
	Kind            string    `json:"kind"`
	Statement       string    `json:"statement"`
	HypothesisID    ID        `json:"hypothesis_id,omitempty"`
	EvidenceIDs     []ID      `json:"evidence_ids,omitempty"`
	CandidateIDs    []string  `json:"candidate_ids,omitempty"`
	Status          string    `json:"status"`
	Uncertainty     []string  `json:"uncertainty,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type ClaimValidation struct {
	ClaimID     string    `json:"claim_id"`
	Valid       bool      `json:"valid"`
	Reasons     []string  `json:"reasons,omitempty"`
	ValidatedAt time.Time `json:"validated_at"`
}

type Activity struct {
	ID              string         `json:"id"`
	InvestigationID ID             `json:"investigation_id"`
	Type            string         `json:"type"`
	ObjectiveID     string         `json:"objective_id,omitempty"`
	Status          ActivityStatus `json:"status"`
	InputRefs       []string       `json:"input_refs,omitempty"`
	OutputRefs      []string       `json:"output_refs,omitempty"`
	DependencyIDs   []string       `json:"dependency_ids,omitempty"`
	AttemptCount    int            `json:"attempt_count"`
	SelectionReason string         `json:"selection_reason,omitempty"`
	Error           string         `json:"error,omitempty"`
	StartedAt       *time.Time     `json:"started_at,omitempty"`
	CompletedAt     *time.Time     `json:"completed_at,omitempty"`
	Executed        bool           `json:"executed"`
	Advanced        bool           `json:"advanced"`
	Resolved        bool           `json:"resolved"`
	Refuted         bool           `json:"refuted"`
	Missing         []string       `json:"missing,omitempty"`
}

type InvestigationBudget struct {
	MaxIterations   int           `json:"max_iterations"`
	MaxActivities   int           `json:"max_activities"`
	MaxExperiments  int           `json:"max_experiments"`
	MaxDuration     time.Duration `json:"max_duration"`
	IterationsUsed  int           `json:"iterations_used"`
	ActivitiesUsed  int           `json:"activities_used"`
	ExperimentsUsed int           `json:"experiments_used"`
}

type InvestigationQuestion struct {
	ID              string `json:"id"`
	Statement       string `json:"statement"`
	HypothesisIDs   []ID   `json:"hypothesis_ids,omitempty"`
	MissingEvidence []ID   `json:"missing_evidence,omitempty"`
	Resolved        bool   `json:"resolved"`
}

// AdaptiveState is the durable checkpoint for the adaptive investigation
// loop. It is separate from repository knowledge and from individual
// activities so a resumed process can reconstruct its decision context.
type AdaptiveState struct {
	InvestigationID     ID                          `json:"investigation_id"`
	Questions           []InvestigationQuestion     `json:"questions,omitempty"`
	Objectives          []AdaptiveObjective         `json:"objectives,omitempty"`
	Budget              InvestigationBudget         `json:"budget"`
	StoppingReason      string                      `json:"stopping_reason,omitempty"`
	TerminalExplanation *TerminalInvestigationState `json:"terminal_explanation,omitempty"`
	Iterations          int                         `json:"iterations"`
	UpdatedAt           time.Time                   `json:"updated_at"`
}

// TerminalInvestigationState is the durable, machine-readable explanation for
// why a controller stopped. It deliberately records unresolved dependencies
// separately from actions that were not run, so an incomplete diagnosis cannot
// be mistaken for a completed one.
type TerminalInvestigationState struct {
	Reason                 string                     `json:"reason"`
	Summary                string                     `json:"summary,omitempty"`
	UnresolvedDependencies []InvestigationDependency  `json:"unresolved_dependencies,omitempty"`
	ActionsNotAttempted    []InvestigationDisposition `json:"actions_not_attempted,omitempty"`
	Budget                 InvestigationBudget        `json:"budget"`
}

type InvestigationDependency struct {
	ID               string   `json:"id"`
	Predicate        string   `json:"predicate,omitempty"`
	Status           string   `json:"status"`
	RequiredEvidence []string `json:"required_evidence,omitempty"`
	Evaluation       string   `json:"evaluation,omitempty"`
	NextAction       string   `json:"next_action,omitempty"`
}

type InvestigationDisposition struct {
	ActionType string   `json:"action_type"`
	Target     string   `json:"target,omitempty"`
	Status     string   `json:"status"` // unavailable, blocked, excluded_by_budget
	Reason     string   `json:"reason"`
	UnknownIDs []string `json:"unknown_ids,omitempty"`
}

// AdaptiveObjective is the durable checkpoint for one causal unknown.
// Objective resolution is independent from action completion.
type AdaptiveObjective struct {
	ID                  string                `json:"id"`
	Question            string                `json:"question"`
	Predicate           string                `json:"predicate"`
	Status              string                `json:"status"`
	EvidenceIDs         []ID                  `json:"evidence_ids,omitempty"`
	ResolutionEvidence  []ID                  `json:"resolution_evidence_ids,omitempty"`
	Evaluation          string                `json:"evaluation,omitempty"`
	Revision            string                `json:"revision,omitempty"`
	NextAction          string                `json:"next_action,omitempty"`
	CandidateActions    []string              `json:"candidate_actions,omitempty"`
	RequiredEvidence    []string              `json:"required_evidence,omitempty"`
	Target              string                `json:"target,omitempty"`
	TargetSymbol        string                `json:"target_symbol,omitempty"`
	Requirements        []EvidenceRequirement `json:"requirements,omitempty"`
	MissingRequirements []string              `json:"missing_requirements,omitempty"`
	RefutedBy           []ID                  `json:"refuted_by,omitempty"`
}

// EvidenceRequirement is an optional strict contract for causal objectives.
// Legacy objectives continue to use RequiredEvidence.
type EvidenceRequirement struct {
	ClaimKind    string `json:"claim_kind"`
	Subject      string `json:"subject,omitempty"`
	MinimumBasis string `json:"minimum_basis,omitempty"`
	Revision     string `json:"revision,omitempty"`
	SameInstance bool   `json:"same_instance,omitempty"`
	Ordering     string `json:"ordering,omitempty"`
}

// HistoricalReference points at prior repository knowledge without asserting
// that the old revision contains the same code or cause.
type HistoricalReference struct {
	InvestigationID ID
	FailureID       string
	CandidateID     string
	RevisionID      string
	Similarity      float64
	RelationshipID  string
	EvidenceID      ID
	Uncertainty     string
}
