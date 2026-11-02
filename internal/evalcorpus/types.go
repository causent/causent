package evalcorpus

import "github.com/causent/causent/internal/diagnosis"

type Tier string

const (
	TierLogOnly Tier = "log_only"
	TierFull    Tier = "full"
)

type Category string

const (
	CategoryPreExisting    Category = "pre_existing"
	CategoryRegression     Category = "regression"
	CategoryDependency     Category = "dependency"
	CategoryFlaky          Category = "flaky"
	CategoryInfrastructure Category = "infrastructure"
	CategoryNotReproduced  Category = "not_reproduced"
)

type ExpectedOutcome string

const (
	OutcomeAnswerable           ExpectedOutcome = "answerable"
	OutcomeInsufficientEvidence ExpectedOutcome = "insufficient_evidence"
)

type Manifest struct {
	Version string          `yaml:"version"`
	Cases   []ManifestEntry `yaml:"cases"`
}

type ManifestEntry struct {
	ID       string   `yaml:"id"`
	Tier     Tier     `yaml:"tier"`
	Category Category `yaml:"category"`
}

type Metadata struct {
	ID           string   `yaml:"id"`
	Tier         Tier     `yaml:"tier"`
	Category     Category `yaml:"category"`
	Repo         string   `yaml:"repo"`
	RunURL       string   `yaml:"run_url"`
	LogSHA256    string   `yaml:"log_sha256"`
	HeadSHA      string   `yaml:"head_sha"`
	BaseSHA      string   `yaml:"base_sha"`
	Command      []string `yaml:"command"`
	LicenseNote  string   `yaml:"license_note"`
	Redacted     bool     `yaml:"redacted"`
	LogCachePath string   `yaml:"log_cache_path"`
}

type Expected struct {
	PrimaryFailure    string          `yaml:"primary_failure"`
	Category          Category        `yaml:"category"`
	ExpectedOutcome   ExpectedOutcome `yaml:"expected_outcome"`
	CulpritCommit     string          `yaml:"culprit_commit"`
	CulpritFile       string          `yaml:"culprit_file"`
	CulpritPackage    string          `yaml:"culprit_package"`
	EvidenceSource    string          `yaml:"evidence_source"`
	Annotator         string          `yaml:"annotator"`
	DisagreementNotes string          `yaml:"disagreement_notes"`
}

// RunnerInput intentionally contains no expected answer or ground truth.
// Runners can receive only failure evidence and public case metadata.
type RunnerInput struct {
	FailureLog string
	Metadata   Metadata
}

type Case struct {
	Dir      string
	Metadata Metadata
	Input    RunnerInput
}

type Outcome string

const (
	Correct               Outcome = "correct"
	Wrong                 Outcome = "wrong"
	JustifiedAbstention   Outcome = "justified_abstention"
	UnjustifiedAbstention Outcome = "unjustified_abstention"
)

type Score struct {
	CaseID  string  `json:"case_id"`
	Outcome Outcome `json:"outcome"`
	Reason  string  `json:"reason"`
}

type Counts struct {
	Correct               int     `json:"correct"`
	Wrong                 int     `json:"wrong"`
	JustifiedAbstention   int     `json:"justified_abstention"`
	UnjustifiedAbstention int     `json:"unjustified_abstention"`
	Total                 int     `json:"total"`
	CorrectRate           float64 `json:"correct_rate"`
	WrongRate             float64 `json:"wrong_rate"`
	JustifiedRate         float64 `json:"justified_abstention_rate"`
	UnjustifiedRate       float64 `json:"unjustified_abstention_rate"`
}

func (c *Counts) Add(score Score) {
	c.Total++
	switch score.Outcome {
	case Correct:
		c.Correct++
	case Wrong:
		c.Wrong++
	case JustifiedAbstention:
		c.JustifiedAbstention++
	case UnjustifiedAbstention:
		c.UnjustifiedAbstention++
	}
	if c.Total > 0 {
		c.CorrectRate = float64(c.Correct) / float64(c.Total)
		c.WrongRate = float64(c.Wrong) / float64(c.Total)
		c.JustifiedRate = float64(c.JustifiedAbstention) / float64(c.Total)
		c.UnjustifiedRate = float64(c.UnjustifiedAbstention) / float64(c.Total)
	}
}

// Result is the narrow scorer-facing alias. It keeps callers explicit about
// which production result is being evaluated without changing diagnosis.Report.
type Result = diagnosis.Report
