package persistence

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/causent/causent/internal/domain"
	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db            *sql.DB
	artifactsRoot string
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure SQLite WAL mode: %w", err)
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

// NewID generates a new unique identifier.
func NewID() domain.ID {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	return domain.ID(time.Now().UTC().Format("20060102T150405.000000000") + "-" + hex.EncodeToString(buf))
}

// Config helpers
func (s *Store) setConfig(key, value string) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO config (key, value) VALUES (?,?)`, key, value)
	return err
}

func (s *Store) getConfig(key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM config WHERE key=?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (s *Store) migrate() error {
	//Create migration tracking table
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`); err != nil {
		return fmt.Errorf("create config: %w", err)
	}

	currentVersion, _ := s.getSchemaVersion()

	//Apply migrations in order - all version 1 migrations
	migrations := []struct {
		version int
		sql     string
	}{
		{1, `CREATE TABLE IF NOT EXISTS investigations (
			id TEXT PRIMARY KEY,
			repo_path TEXT NOT NULL,
			command TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			budget_steps INTEGER DEFAULT 0,
			budget_used INTEGER DEFAULT 0
		)`},
		{1, `CREATE TABLE IF NOT EXISTS reproductions (
			investigation_id TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			FOREIGN KEY(investigation_id) REFERENCES investigations(id)
		)`},
		{1, `CREATE TABLE IF NOT EXISTS evidence (
			id TEXT PRIMARY KEY,
			investigation_id TEXT NOT NULL,
			type TEXT NOT NULL,
			source TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			content_ref TEXT NOT NULL,
			digest TEXT,
			payload TEXT NOT NULL DEFAULT '',
			artifact_id TEXT,
			related_hypotheses TEXT DEFAULT '[]',
			related_experiments TEXT DEFAULT '[]',
			FOREIGN KEY(investigation_id) REFERENCES investigations(id)
		)`},
		{1, `CREATE TABLE IF NOT EXISTS hypotheses (
			id TEXT PRIMARY KEY,
			investigation_id TEXT NOT NULL,
			statement TEXT NOT NULL,
			affected_component TEXT,
			supporting_evidence_ids TEXT DEFAULT '[]',
			contradicting_evidence_ids TEXT DEFAULT '[]',
			predicted_observations TEXT DEFAULT '[]',
			confidence REAL NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			experiment_ids TEXT DEFAULT '[]',
			FOREIGN KEY(investigation_id) REFERENCES investigations(id)
		)`},
		{1, `CREATE TABLE IF NOT EXISTS experiments (
			id TEXT PRIMARY KEY,
			investigation_id TEXT NOT NULL,
			type TEXT NOT NULL,
			purpose TEXT NOT NULL,
			hypotheses_ids TEXT DEFAULT '[]',
			command TEXT,
			working_dir TEXT,
			expected_under_hypothesis TEXT DEFAULT '{}',
			timeout TEXT NOT NULL,
			max_output INTEGER NOT NULL,
			status TEXT NOT NULL,
			outcome TEXT,
			result TEXT,
			evidence_produced TEXT DEFAULT '[]',
			created_at TEXT NOT NULL,
			started_at TEXT,
			finished_at TEXT,
			error TEXT,
			FOREIGN KEY(investigation_id) REFERENCES investigations(id)
		)`},
		{1, `CREATE TABLE IF NOT EXISTS patches (
			id TEXT PRIMARY KEY,
			investigation_id TEXT NOT NULL,
			diff TEXT NOT NULL,
			diff_path TEXT,
			workspace_path TEXT,
			status TEXT NOT NULL,
			original_test_result TEXT,
			regression_results TEXT DEFAULT '[]',
			created_at TEXT NOT NULL,
			verified_at TEXT,
			error TEXT,
			FOREIGN KEY(investigation_id) REFERENCES investigations(id)
		)`},
		{1, `CREATE TABLE IF NOT EXISTS investigation_events (
			id TEXT PRIMARY KEY,
			investigation_id TEXT NOT NULL,
			previous_status TEXT NOT NULL,
			next_status TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			trigger TEXT NOT NULL,
			experiment_id TEXT,
			evidence_id TEXT,
			error TEXT,
			FOREIGN KEY(investigation_id) REFERENCES investigations(id)
		)`},
		{1, `CREATE TABLE IF NOT EXISTS artifacts (
			id TEXT PRIMARY KEY,
			investigation_id TEXT NOT NULL,
			type TEXT NOT NULL,
			path TEXT NOT NULL,
			size INTEGER NOT NULL,
			digest TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY(investigation_id) REFERENCES investigations(id)
		)`},
		{1, `CREATE INDEX IF NOT EXISTS idx_evidence_inv ON evidence(investigation_id)`},
		{1, `CREATE INDEX IF NOT EXISTS idx_hypotheses_inv ON hypotheses(investigation_id)`},
		{1, `CREATE INDEX IF NOT EXISTS idx_experiments_inv ON experiments(investigation_id)`},
		{1, `CREATE INDEX IF NOT EXISTS idx_experiments_status ON experiments(status)`},
		{1, `CREATE INDEX IF NOT EXISTS idx_events_inv ON investigation_events(investigation_id)`},
		{1, `CREATE INDEX IF NOT EXISTS idx_patches_inv ON patches(investigation_id)`},
		{1, `CREATE INDEX IF NOT EXISTS idx_artifacts_inv ON artifacts(investigation_id)`},
		{1, `CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(type)`},
		{2, `CREATE TABLE IF NOT EXISTS experiment_details (
			experiment_id TEXT PRIMARY KEY,
			state TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			predictions TEXT NOT NULL DEFAULT '{}',
			observations TEXT NOT NULL DEFAULT '',
			evaluation TEXT NOT NULL DEFAULT '',
			selection_reason TEXT NOT NULL DEFAULT '',
			required_permissions TEXT NOT NULL DEFAULT '[]',
			FOREIGN KEY(experiment_id) REFERENCES experiments(id)
		)`},
		{2, `CREATE TABLE IF NOT EXISTS experiment_transitions (
			id TEXT PRIMARY KEY,
			experiment_id TEXT NOT NULL,
			investigation_id TEXT NOT NULL,
			from_state TEXT NOT NULL,
			to_state TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			FOREIGN KEY(experiment_id) REFERENCES experiments(id)
		)`},
		{2, `CREATE TABLE IF NOT EXISTS hypothesis_history (
			id TEXT PRIMARY KEY,
			hypothesis_id TEXT NOT NULL,
			investigation_id TEXT NOT NULL,
			previous_status TEXT NOT NULL,
			next_status TEXT NOT NULL,
			previous_confidence REAL NOT NULL,
			next_confidence REAL NOT NULL,
			experiment_id TEXT NOT NULL,
			evaluation TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(id)
		)`},
		{2, `CREATE INDEX IF NOT EXISTS idx_experiment_transitions_experiment ON experiment_transitions(experiment_id)`},
		{2, `CREATE INDEX IF NOT EXISTS idx_hypothesis_history_hypothesis ON hypothesis_history(hypothesis_id)`},
		{3, `CREATE TABLE IF NOT EXISTS patch_details (
			patch_id TEXT PRIMARY KEY,
			hypothesis_ids TEXT NOT NULL DEFAULT '[]',
			explanation TEXT NOT NULL DEFAULT '',
			expected_behavior TEXT NOT NULL DEFAULT '',
			changed_files TEXT NOT NULL DEFAULT '[]',
			digest TEXT NOT NULL DEFAULT '',
			base_revision TEXT NOT NULL DEFAULT '',
			provider TEXT NOT NULL DEFAULT '{}',
			validation_status TEXT NOT NULL DEFAULT '',
			application_status TEXT NOT NULL DEFAULT '',
			verification_status TEXT NOT NULL DEFAULT '',
			verification_report TEXT NOT NULL DEFAULT '',
			FOREIGN KEY(patch_id) REFERENCES patches(id)
		)`},
		{3, `CREATE TABLE IF NOT EXISTS verification_reports (
			patch_id TEXT PRIMARY KEY,
			data TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY(patch_id) REFERENCES patches(id)
		)`},
		{4, `CREATE TABLE IF NOT EXISTS benchmark_suites (
			id TEXT PRIMARY KEY, version TEXT NOT NULL, description TEXT NOT NULL, data TEXT NOT NULL
		)`},
		{4, `CREATE TABLE IF NOT EXISTS benchmark_cases (
			id TEXT PRIMARY KEY, suite_id TEXT NOT NULL, version TEXT NOT NULL, data TEXT NOT NULL,
			FOREIGN KEY(suite_id) REFERENCES benchmark_suites(id)
		)`},
		{4, `CREATE TABLE IF NOT EXISTS evaluation_trials (
			id TEXT PRIMARY KEY, evaluation_id TEXT NOT NULL, case_id TEXT NOT NULL,
			strategy TEXT NOT NULL, outcome TEXT NOT NULL, data TEXT NOT NULL, started_at TEXT NOT NULL,
			FOREIGN KEY(case_id) REFERENCES benchmark_cases(id)
		)`},
		{4, `CREATE TABLE IF NOT EXISTS evaluation_summaries (
			evaluation_id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at TEXT NOT NULL
		)`},
	}

	for _, m := range migrations {
		if currentVersion >= m.version {
			continue
		}
		// Provenance is kept in side tables so version-one databases remain
		// readable without a destructive schema rewrite.
		if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS hypothesis_provenance (hypothesis_id TEXT PRIMARY KEY, provenance TEXT NOT NULL)`); err != nil {
			return fmt.Errorf("create hypothesis provenance: %w", err)
		}
		if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS evidence_provenance (evidence_id TEXT PRIMARY KEY, provenance TEXT NOT NULL)`); err != nil {
			return fmt.Errorf("create evidence provenance: %w", err)
		}
		if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS model_metadata (investigation_id TEXT PRIMARY KEY, provider TEXT NOT NULL, model TEXT NOT NULL, endpoint TEXT NOT NULL, request_id TEXT NOT NULL)`); err != nil {
			return fmt.Errorf("create model metadata: %w", err)
		}
		if _, err := s.db.Exec(m.sql); err != nil {
			return fmt.Errorf("migration %d: %w", m.version, err)
		}
		if _, err := s.db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?,?) ON CONFLICT(version) DO NOTHING`, m.version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}
		slog.Info("applied schema migration", "version", m.version)
	}
	// Older databases created before budget accounting did not have these
	// columns. CREATE TABLE IF NOT EXISTS does not alter an existing table, so
	// upgrade them explicitly and keep existing investigation data intact.
	for _, column := range []struct {
		name string
		def  string
	}{
		{name: "budget_steps", def: "INTEGER DEFAULT 0"},
		{name: "budget_used", def: "INTEGER DEFAULT 0"},
	} {
		var present int
		err := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('investigations') WHERE name=?`, column.name).Scan(&present)
		if err != nil {
			return fmt.Errorf("inspect investigations schema: %w", err)
		}
		if present == 0 {
			if _, err := s.db.Exec(`ALTER TABLE investigations ADD COLUMN ` + column.name + ` ` + column.def); err != nil {
				return fmt.Errorf("add investigations.%s: %w", column.name, err)
			}
		}
	}

	//Set artifacts root
	artifactsRoot := os.Getenv("CAUSENT_ARTIFACTS_ROOT")
	if artifactsRoot == "" {
		home, _ := os.UserHomeDir()
		artifactsRoot = filepath.Join(home, ".causent", "artifacts")
	}
	s.artifactsRoot = artifactsRoot
	s.setConfig("artifacts_root", artifactsRoot)

	//Ensure artifacts directory exists
	os.MkdirAll(artifactsRoot, 0700)

	_ = currentVersion
	return nil
}

func (s *Store) getSchemaVersion() (int, error) {
	var version int
	err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version)
	return version, err
}

// Helper to convert []string to []domain.ID
func parseIDSlice(s string) []domain.ID {
	var ids []string
	if err := json.Unmarshal([]byte(s), &ids); err != nil {
		return nil
	}
	result := make([]domain.ID, len(ids))
	for i, id := range ids {
		result[i] = domain.ID(id)
	}
	return result
}

// SaveInvestigation saves or updates an investigation.
func (s *Store) SaveInvestigation(inv domain.Investigation) error {
	_, err := s.db.Exec(
		`INSERT INTO investigations (id, repo_path, command, status, created_at, updated_at, budget_steps, budget_used)
		 VALUES (?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at, budget_steps=excluded.budget_steps, budget_used=excluded.budget_used`,
		inv.ID, inv.RepoPath, mustJSON(inv.Command), string(inv.Status),
		inv.CreatedAt.UTC().Format(time.RFC3339Nano), inv.UpdatedAt.UTC().Format(time.RFC3339Nano),
		inv.BudgetSteps, inv.BudgetUsed,
	)
	return err
}

// GetInvestigation retrieves an investigation by ID.
func (s *Store) GetInvestigation(id domain.ID) (domain.Investigation, error) {
	row := s.db.QueryRow(`SELECT id, repo_path, command, status, created_at, updated_at, budget_steps, budget_used FROM investigations WHERE id=?`, id)
	var inv domain.Investigation
	var cmdJSON, created, updated string
	if err := row.Scan(&inv.ID, &inv.RepoPath, &cmdJSON, &inv.Status, &created, &updated, &inv.BudgetSteps, &inv.BudgetUsed); err != nil {
		return inv, err
	}

	if err := json.Unmarshal([]byte(cmdJSON), &inv.Command); err != nil {
		return inv, err
	}
	inv.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	inv.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return inv, nil
}

func (s *Store) ListInvestigations(limit, offset int) ([]domain.Investigation, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(`SELECT id, repo_path, command, status, created_at, updated_at, budget_steps, budget_used FROM investigations ORDER BY updated_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Investigation
	for rows.Next() {
		var inv domain.Investigation
		var cmdJSON, created, updated string
		if err := rows.Scan(&inv.ID, &inv.RepoPath, &cmdJSON, &inv.Status, &created, &updated, &inv.BudgetSteps, &inv.BudgetUsed); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(cmdJSON), &inv.Command); err != nil {
			return nil, err
		}
		inv.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		inv.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		out = append(out, inv)
	}
	return out, rows.Err()
}

// ListIncompleteInvestigations returns investigations that were interrupted.
func (s *Store) ListIncompleteInvestigations() ([]domain.Investigation, error) {
	rows, err := s.db.Query(`SELECT id, repo_path, command, status, created_at, updated_at, budget_steps, budget_used FROM investigations
		WHERE status NOT IN (?,?,?,?,?,?) ORDER BY updated_at DESC`,
		string(domain.StatusCompleted), string(domain.StatusInconclusive),
		string(domain.StatusReproFailed), string(domain.StatusExecutionFailed),
		string(domain.StatusBudgetExhausted), string(domain.StatusCancelled))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Investigation
	for rows.Next() {
		var inv domain.Investigation
		var cmdJSON, created, updated string
		if err := rows.Scan(&inv.ID, &inv.RepoPath, &cmdJSON, &inv.Status, &created, &updated, &inv.BudgetSteps, &inv.BudgetUsed); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(cmdJSON), &inv.Command); err != nil {
			return nil, err
		}
		inv.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		inv.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
		out = append(out, inv)
	}
	return out, rows.Err()
}

// SaveReproduction saves or updates a reproduction record.
func (s *Store) SaveReproduction(rep domain.Reproduction) error {
	data, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO reproductions (investigation_id, data) VALUES (?,?) ON CONFLICT(investigation_id) DO UPDATE SET data=excluded.data`,
		rep.InvestigationID, string(data),
	)
	return err
}

// GetReproduction retrieves a reproduction record.
func (s *Store) GetReproduction(id domain.ID) (domain.Reproduction, error) {
	var data string
	err := s.db.QueryRow(`SELECT data FROM reproductions WHERE investigation_id=?`, id).Scan(&data)
	if err != nil {
		return domain.Reproduction{}, err
	}
	var rep domain.Reproduction
	if err := json.Unmarshal([]byte(data), &rep); err != nil {
		return rep, err
	}
	return rep, nil
}

// SaveEvidence saves an evidence record.
func (s *Store) SaveEvidence(e domain.Evidence) error {
	_, err := s.db.Exec(
		`INSERT INTO evidence (id, investigation_id, type, source, timestamp, content_ref, digest, payload, artifact_id, related_hypotheses, related_experiments)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, artifact_id=excluded.artifact_id`,
		e.ID, e.InvestigationID, string(e.Type), e.Source,
		e.Timestamp.UTC().Format(time.RFC3339Nano), e.ContentRef, e.Digest, e.Payload, string(e.ArtifactID),
		mustJSON(e.RelatedHypotheses), mustJSON(e.RelatedExperiments),
	)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO evidence_provenance (evidence_id, provenance) VALUES (?,?) ON CONFLICT(evidence_id) DO UPDATE SET provenance=excluded.provenance`, e.ID, e.Provenance)
	return err
}

// ListEvidence returns all evidence for an investigation.
func (s *Store) ListEvidence(invID domain.ID) ([]domain.Evidence, error) {
	rows, err := s.db.Query(`SELECT id, investigation_id, type, source, timestamp, content_ref, digest, payload, artifact_id, related_hypotheses, related_experiments FROM evidence WHERE investigation_id=?`, invID)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	var out []domain.Evidence
	for rows.Next() {
		var e domain.Evidence
		var ts, ref, digest, payload, artifactID, rh, re string
		if err := rows.Scan(&e.ID, &e.InvestigationID, &e.Type, &e.Source, &ts, &ref, &digest, &payload, &artifactID, &rh, &re); err != nil {
			return nil, err
		}
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		e.ContentRef = ref
		e.Digest = digest
		e.Payload = payload
		e.ArtifactID = domain.ID(artifactID)
		json.Unmarshal([]byte(rh), &e.RelatedHypotheses)
		json.Unmarshal([]byte(re), &e.RelatedExperiments)
		if err := s.db.QueryRow(`SELECT provenance FROM evidence_provenance WHERE evidence_id=?`, e.ID).Scan(&e.Provenance); err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) GetEvidence(id domain.ID) (domain.Evidence, error) {
	var e domain.Evidence
	var timestamp, relatedHypotheses, relatedExperiments string
	err := s.db.QueryRow(`SELECT id, investigation_id, type, source, timestamp, content_ref, digest, payload, artifact_id, related_hypotheses, related_experiments FROM evidence WHERE id=?`, id).Scan(&e.ID, &e.InvestigationID, &e.Type, &e.Source, &timestamp, &e.ContentRef, &e.Digest, &e.Payload, &e.ArtifactID, &relatedHypotheses, &relatedExperiments)
	if err != nil {
		return e, err
	}
	e.Timestamp, _ = time.Parse(time.RFC3339Nano, timestamp)
	e.RelatedHypotheses = parseIDSlice(relatedHypotheses)
	e.RelatedExperiments = parseIDSlice(relatedExperiments)
	var provenance string
	_ = s.db.QueryRow(`SELECT provenance FROM evidence_provenance WHERE evidence_id=?`, id).Scan(&provenance)
	e.Provenance = provenance
	return e, nil
}

// SaveModelMetadata persists the provider identity used for an investigation.
func (s *Store) SaveModelMetadata(invID domain.ID, metadata domain.ModelMetadata) error {
	_, err := s.db.Exec(`INSERT INTO model_metadata (investigation_id, provider, model, endpoint, request_id) VALUES (?,?,?,?,?) ON CONFLICT(investigation_id) DO UPDATE SET provider=excluded.provider, model=excluded.model, endpoint=excluded.endpoint, request_id=excluded.request_id`, invID, metadata.Provider, metadata.Model, metadata.Endpoint, metadata.RequestID)
	return err
}

func (s *Store) GetModelMetadata(invID domain.ID) (domain.ModelMetadata, error) {
	var metadata domain.ModelMetadata
	err := s.db.QueryRow(`SELECT provider, model, endpoint, request_id FROM model_metadata WHERE investigation_id=?`, invID).Scan(&metadata.Provider, &metadata.Model, &metadata.Endpoint, &metadata.RequestID)
	return metadata, err
}

// SaveHypothesis saves or updates a hypothesis.
func (s *Store) SaveHypothesis(h domain.Hypothesis) error {
	_, err := s.db.Exec(
		`INSERT INTO hypotheses (id, investigation_id, statement, affected_component, supporting_evidence_ids, contradicting_evidence_ids, predicted_observations, confidence, status, created_at, updated_at, experiment_ids)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at, supporting_evidence_ids=excluded.supporting_evidence_ids, contradicting_evidence_ids=excluded.contradicting_evidence_ids, experiment_ids=excluded.experiment_ids, confidence=excluded.confidence`,
		h.ID, h.InvestigationID, h.Statement, h.AffectedComponent,
		mustJSON(h.SupportingEvidenceIDs), mustJSON(h.ContradictingEvidenceIDs),
		mustJSON(h.PredictedObservations), h.Confidence, string(h.Status),
		h.CreatedAt.UTC().Format(time.RFC3339Nano), h.UpdatedAt.UTC().Format(time.RFC3339Nano),
		mustJSON(h.ExperimentIDs),
	)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO hypothesis_provenance (hypothesis_id, provenance) VALUES (?,?) ON CONFLICT(hypothesis_id) DO UPDATE SET provenance=excluded.provenance`, h.ID, h.Provenance)
	return err
}

// ListHypotheses returns all hypotheses for an investigation.
func (s *Store) ListHypotheses(invID domain.ID) ([]domain.Hypothesis, error) {
	rows, err := s.db.Query(`SELECT id, investigation_id, statement, affected_component, supporting_evidence_ids, contradicting_evidence_ids, predicted_observations, confidence, status, created_at, updated_at, experiment_ids FROM hypotheses WHERE investigation_id=?`, invID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Hypothesis
	for rows.Next() {
		var h domain.Hypothesis
		var se, ce, po, ea string
		var ca, ua string
		if err := rows.Scan(&h.ID, &h.InvestigationID, &h.Statement, &h.AffectedComponent, &se, &ce, &po, &h.Confidence, &h.Status, &ca, &ua, &ea); err != nil {
			return nil, err
		}
		h.CreatedAt, _ = time.Parse(time.RFC3339Nano, ca)
		h.UpdatedAt, _ = time.Parse(time.RFC3339Nano, ua)
		h.SupportingEvidenceIDs = parseIDSlice(se)
		h.ContradictingEvidenceIDs = parseIDSlice(ce)
		h.PredictedObservations = mustParseStrings(po)
		h.ExperimentIDs = parseIDSlice(ea)
		if err := s.db.QueryRow(`SELECT provenance FROM hypothesis_provenance WHERE hypothesis_id=?`, h.ID).Scan(&h.Provenance); err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SaveExperiment saves or updates an experiment.
func (s *Store) SaveExperiment(ex domain.Experiment) error {
	resJSON, err := json.Marshal(ex.Result)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO experiments (id, investigation_id, type, purpose, hypotheses_ids, command, working_dir, expected_under_hypothesis, timeout, max_output, status, outcome, result, evidence_produced, created_at, started_at, finished_at, error)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET status=excluded.status, outcome=excluded.outcome, result=excluded.result, evidence_produced=excluded.evidence_produced, finished_at=excluded.finished_at, error=excluded.error`,
		ex.ID, ex.InvestigationID, string(ex.Type), string(ex.Purpose), mustJSON(ex.HypothesesIDs),
		mustJSON(ex.Command), ex.WorkingDir, mustJSON(ex.ExpectedUnderHypothesis),
		ex.Timeout.String(), ex.MaxOutput, string(ex.Status), string(ex.Outcome),
		string(resJSON), mustJSON(ex.EvidenceProduced),
		ex.CreatedAt.UTC().Format(time.RFC3339Nano),
		optTimePtr(ex.StartedAt), optTimePtr(ex.FinishedAt), ex.Error,
	)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO experiment_details (experiment_id, state, description, predictions, observations, evaluation, selection_reason, required_permissions)
		VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(experiment_id) DO UPDATE SET state=excluded.state, description=excluded.description, predictions=excluded.predictions, observations=excluded.observations, evaluation=excluded.evaluation, selection_reason=excluded.selection_reason, required_permissions=excluded.required_permissions`,
		ex.ID, string(ex.State), ex.Description, mustJSON(ex.Predictions), ex.Observations, ex.Evaluation, ex.SelectionReason, mustJSON(ex.RequiredPermissions))
	return err
}

func (s *Store) TransitionExperiment(experimentID, investigationID domain.ID, from, to domain.ExperimentState, reason string) error {
	if err := domain.ValidateExperimentTransition(from, to); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO experiment_transitions (id, experiment_id, investigation_id, from_state, to_state, timestamp, reason) VALUES (?,?,?,?,?,?,?)`,
		NewID(), experimentID, investigationID, string(from), string(to), time.Now().UTC().Format(time.RFC3339Nano), reason)
	return err
}

func (s *Store) ListExperimentTransitions(id domain.ID) ([]domain.InvestigationEvent, error) {
	rows, err := s.db.Query(`SELECT id, investigation_id, from_state, to_state, timestamp, reason FROM experiment_transitions WHERE experiment_id=? ORDER BY timestamp`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.InvestigationEvent
	for rows.Next() {
		var ev domain.InvestigationEvent
		var from, to, timestamp string
		if err := rows.Scan(&ev.ID, &ev.InvestigationID, &from, &to, &timestamp, &ev.Error); err != nil {
			return nil, err
		}
		ev.PreviousStatus = domain.Status(from)
		ev.NextStatus = domain.Status(to)
		ev.Timestamp, _ = time.Parse(time.RFC3339Nano, timestamp)
		ev.ExperimentID = id
		ev.Trigger = "experiment_state_transition"
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *Store) SaveHypothesisHistory(history domain.HypothesisHistory) error {
	_, err := s.db.Exec(`INSERT INTO hypothesis_history (id, hypothesis_id, investigation_id, previous_status, next_status, previous_confidence, next_confidence, experiment_id, evaluation, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		history.ID, history.HypothesisID, history.InvestigationID, history.PreviousStatus, history.NextStatus, history.PreviousConfidence, history.NextConfidence, history.ExperimentID, history.Evaluation, history.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) ListHypothesisHistory(id domain.ID) ([]domain.HypothesisHistory, error) {
	rows, err := s.db.Query(`SELECT id, hypothesis_id, investigation_id, previous_status, next_status, previous_confidence, next_confidence, experiment_id, evaluation, created_at FROM hypothesis_history WHERE hypothesis_id=? ORDER BY created_at`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.HypothesisHistory
	for rows.Next() {
		var h domain.HypothesisHistory
		var created string
		if err := rows.Scan(&h.ID, &h.HypothesisID, &h.InvestigationID, &h.PreviousStatus, &h.NextStatus, &h.PreviousConfidence, &h.NextConfidence, &h.ExperimentID, &h.Evaluation, &created); err != nil {
			return nil, err
		}
		h.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, h)
	}
	return out, rows.Err()
}

// ListExperiments returns all experiments for an investigation.
func (s *Store) ListExperiments(invID domain.ID) ([]domain.Experiment, error) {
	rows, err := s.db.Query(`SELECT id, investigation_id, type, purpose, hypotheses_ids, command, working_dir, expected_under_hypothesis, timeout, max_output, status, outcome, result, evidence_produced, created_at, started_at, finished_at, error FROM experiments WHERE investigation_id=?`, invID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Experiment
	for rows.Next() {
		var ex domain.Experiment
		var hypothesesIDs, cmdJSON, wd, euh, timeout, resultJSON, evp, created, sa, fa, errStr string
		if err := rows.Scan(&ex.ID, &ex.InvestigationID, &ex.Type, &ex.Purpose, &hypothesesIDs, &cmdJSON, &wd, &euh, &timeout, &ex.MaxOutput, &ex.Status, &ex.Outcome, &resultJSON, &evp, &created, &sa, &fa, &errStr); err != nil {
			return nil, err
		}
		ex.HypothesesIDs = parseIDSlice(hypothesesIDs)
		if cmdJSON != "" {
			json.Unmarshal([]byte(cmdJSON), &ex.Command)
		}
		ex.WorkingDir = wd
		json.Unmarshal([]byte(euh), &ex.ExpectedUnderHypothesis)
		ex.Timeout, _ = time.ParseDuration(timeout)
		ex.EvidenceProduced = parseIDSlice(evp)
		ex.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if sa != "" {
			t, _ := time.Parse(time.RFC3339Nano, sa)
			ex.StartedAt = &t
		}
		if fa != "" {
			t, _ := time.Parse(time.RFC3339Nano, fa)
			ex.FinishedAt = &t
		}
		ex.Error = errStr
		if resultJSON != "" {
			json.Unmarshal([]byte(resultJSON), &ex.Result)
		}
		if err := s.loadExperimentDetails(&ex); err != nil {
			return nil, err
		}
		out = append(out, ex)
	}
	return out, rows.Err()
}

// GetExperiment retrieves a single experiment by ID.
func (s *Store) GetExperiment(id domain.ID) (domain.Experiment, error) {
	var ex domain.Experiment
	var hypothesesIDs, cmdJSON, wd, euh, timeout, resultJSON, evp, created, sa, fa, errStr string
	err := s.db.QueryRow(`SELECT id, investigation_id, type, purpose, hypotheses_ids, command, working_dir, expected_under_hypothesis, timeout, max_output, status, outcome, result, evidence_produced, created_at, started_at, finished_at, error FROM experiments WHERE id=?`, id).Scan(
		&ex.ID, &ex.InvestigationID, &ex.Type, &ex.Purpose, &hypothesesIDs, &cmdJSON, &wd, &euh, &timeout, &ex.MaxOutput, &ex.Status, &ex.Outcome, &resultJSON, &evp, &created, &sa, &fa, &errStr,
	)
	if err != nil {
		return ex, err
	}
	ex.HypothesesIDs = parseIDSlice(hypothesesIDs)
	if cmdJSON != "" {
		json.Unmarshal([]byte(cmdJSON), &ex.Command)
	}
	ex.WorkingDir = wd
	json.Unmarshal([]byte(euh), &ex.ExpectedUnderHypothesis)
	ex.Timeout, _ = time.ParseDuration(timeout)
	ex.EvidenceProduced = parseIDSlice(evp)
	ex.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if sa != "" {
		t, _ := time.Parse(time.RFC3339Nano, sa)
		ex.StartedAt = &t
	}
	if fa != "" {
		t, _ := time.Parse(time.RFC3339Nano, fa)
		ex.FinishedAt = &t
	}
	ex.Error = errStr
	if resultJSON != "" {
		json.Unmarshal([]byte(resultJSON), &ex.Result)
	}
	if err := s.loadExperimentDetails(&ex); err != nil {
		return ex, err
	}
	return ex, nil
}

func (s *Store) loadExperimentDetails(ex *domain.Experiment) error {
	var state, predictions, permissions string
	err := s.db.QueryRow(`SELECT state, description, predictions, observations, evaluation, selection_reason, required_permissions FROM experiment_details WHERE experiment_id=?`,
		ex.ID).Scan(&state, &ex.Description, &predictions, &ex.Observations, &ex.Evaluation, &ex.SelectionReason, &permissions)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	ex.State = domain.ExperimentState(state)
	if err := json.Unmarshal([]byte(predictions), &ex.Predictions); err != nil {
		return err
	}
	return json.Unmarshal([]byte(permissions), &ex.RequiredPermissions)
}

// SavePatch saves or updates a patch.
func (s *Store) SavePatch(p domain.Patch) error {
	otr, _ := json.Marshal(p.OriginalTestResult)
	rrs, _ := json.Marshal(p.RegressionResults)
	_, err := s.db.Exec(
		`INSERT INTO patches (id, investigation_id, diff, diff_path, workspace_path, status, original_test_result, regression_results, created_at, verified_at, error)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET diff=excluded.diff, diff_path=excluded.diff_path, workspace_path=excluded.workspace_path, status=excluded.status, original_test_result=excluded.original_test_result, regression_results=excluded.regression_results, verified_at=excluded.verified_at, error=excluded.error`,
		p.ID, p.InvestigationID, p.Diff, p.DiffPath, p.WorkspacePath, string(p.Status),
		string(otr), string(rrs), p.CreatedAt.UTC().Format(time.RFC3339Nano),
		optTimePtr(p.VerifiedAt), p.Error,
	)
	if err != nil {
		return err
	}
	provider, err := json.Marshal(p.Provider)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO patch_details (patch_id, hypothesis_ids, explanation, expected_behavior, changed_files, digest, base_revision, provider, validation_status, application_status, verification_status, verification_report)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(patch_id) DO UPDATE SET hypothesis_ids=excluded.hypothesis_ids, explanation=excluded.explanation, expected_behavior=excluded.expected_behavior, changed_files=excluded.changed_files, digest=excluded.digest, base_revision=excluded.base_revision, provider=excluded.provider, validation_status=excluded.validation_status, application_status=excluded.application_status, verification_status=excluded.verification_status, verification_report=excluded.verification_report`,
		p.ID, mustJSON(p.HypothesisIDs), p.Explanation, p.ExpectedBehavior, mustJSON(p.ChangedFiles), p.Digest, p.BaseRevision, string(provider), p.ValidationStatus, p.ApplicationStatus, p.VerificationStatus, p.VerificationReport)
	return err
}

func (s *Store) SaveVerificationReport(report domain.VerificationReport) error {
	data, err := json.Marshal(report)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO verification_reports (patch_id, data, created_at) VALUES (?,?,?) ON CONFLICT(patch_id) DO UPDATE SET data=excluded.data, created_at=excluded.created_at`, report.PatchID, string(data), report.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) GetVerificationReport(id domain.ID) (domain.VerificationReport, error) {
	var data string
	if err := s.db.QueryRow(`SELECT data FROM verification_reports WHERE patch_id=?`, id).Scan(&data); err != nil {
		return domain.VerificationReport{}, err
	}
	var report domain.VerificationReport
	if err := json.Unmarshal([]byte(data), &report); err != nil {
		return report, err
	}
	return report, nil
}

func (s *Store) loadPatchDetails(p *domain.Patch) error {
	var hypothesisIDs, changedFiles, provider string
	err := s.db.QueryRow(`SELECT hypothesis_ids, explanation, expected_behavior, changed_files, digest, base_revision, provider, validation_status, application_status, verification_status, verification_report FROM patch_details WHERE patch_id=?`,
		p.ID).Scan(&hypothesisIDs, &p.Explanation, &p.ExpectedBehavior, &changedFiles, &p.Digest, &p.BaseRevision, &provider, &p.ValidationStatus, &p.ApplicationStatus, &p.VerificationStatus, &p.VerificationReport)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	p.HypothesisIDs = parseIDSlice(hypothesisIDs)
	if err := json.Unmarshal([]byte(changedFiles), &p.ChangedFiles); err != nil {
		return err
	}
	return json.Unmarshal([]byte(provider), &p.Provider)
}

// GetPatch retrieves a patch by ID.
func (s *Store) GetPatch(id domain.ID) (domain.Patch, error) {
	var p domain.Patch
	var diff, dp, wp, otr, rrs, va, errStr string
	row := s.db.QueryRow(`SELECT id, investigation_id, diff, diff_path, workspace_path, status, original_test_result, regression_results, created_at, verified_at, error FROM patches WHERE id=?`, id)
	if err := row.Scan(&p.ID, &p.InvestigationID, &diff, &dp, &wp, &p.Status, &otr, &rrs, &p.CreatedAt, &va, &errStr); err != nil {
		return p, err
	}
	p.Diff = diff
	p.DiffPath = dp
	p.WorkspacePath = wp
	p.Error = errStr
	p.CreatedAt, _ = time.Parse(time.RFC3339Nano, p.CreatedAt.String())
	if va != "" {
		t, _ := time.Parse(time.RFC3339Nano, va)
		p.VerifiedAt = &t
	}
	json.Unmarshal([]byte(otr), &p.OriginalTestResult)
	json.Unmarshal([]byte(rrs), &p.RegressionResults)
	if err := s.loadPatchDetails(&p); err != nil {
		return p, err
	}
	return p, nil
}

// ListPatches returns all patches for an investigation.
func (s *Store) ListPatches(invID domain.ID) ([]domain.Patch, error) {
	rows, err := s.db.Query(`SELECT id, investigation_id, diff, diff_path, workspace_path, status, original_test_result, regression_results, created_at, verified_at, error FROM patches WHERE investigation_id=?`, invID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Patch
	for rows.Next() {
		var p domain.Patch
		var diff, dp, wp, otr, rrs, va, errStr string
		if err := rows.Scan(&p.ID, &p.InvestigationID, &diff, &dp, &wp, &p.Status, &otr, &rrs, &p.CreatedAt, &va, &errStr); err != nil {
			return nil, err
		}
		p.Diff = diff
		p.DiffPath = dp
		p.WorkspacePath = wp
		p.Error = errStr
		p.CreatedAt, _ = time.Parse(time.RFC3339Nano, p.CreatedAt.String())
		if va != "" {
			t, _ := time.Parse(time.RFC3339Nano, va)
			p.VerifiedAt = &t
		}
		json.Unmarshal([]byte(otr), &p.OriginalTestResult)
		json.Unmarshal([]byte(rrs), &p.RegressionResults)
		if err := s.loadPatchDetails(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SaveEvent saves an investigation event.
func (s *Store) SaveEvent(ev domain.InvestigationEvent) error {
	_, err := s.db.Exec(
		`INSERT INTO investigation_events (id, investigation_id, previous_status, next_status, timestamp, trigger, experiment_id, evidence_id, error)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		ev.ID, ev.InvestigationID, string(ev.PreviousStatus), string(ev.NextStatus),
		ev.Timestamp.UTC().Format(time.RFC3339Nano), ev.Trigger, string(ev.ExperimentID),
		string(ev.EvidenceID), ev.Error,
	)
	return err
}

// ListEvents returns all events for an investigation.
func (s *Store) ListEvents(invID domain.ID) ([]domain.InvestigationEvent, error) {
	rows, err := s.db.Query(`SELECT id, investigation_id, previous_status, next_status, timestamp, trigger, experiment_id, evidence_id, error FROM investigation_events WHERE investigation_id=? ORDER BY timestamp`, invID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.InvestigationEvent
	for rows.Next() {
		var ev domain.InvestigationEvent
		var ts, exid, eid, errStr string
		if err := rows.Scan(&ev.ID, &ev.InvestigationID, &ev.PreviousStatus, &ev.NextStatus, &ts, &ev.Trigger, &exid, &eid, &errStr); err != nil {
			return nil, err
		}
		ev.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		ev.ExperimentID = domain.ID(exid)
		ev.EvidenceID = domain.ID(eid)
		ev.Error = errStr
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ListEventsAfterCursor returns events for an investigation with IDs strictly
// greater than the given cursor, ordered by event ID. This supports cursor-based
// pagination for SSE reconnection without relying on timestamps.
func (s *Store) ListEventsAfterCursor(invID domain.ID, cursor domain.ID) ([]domain.InvestigationEvent, error) {
	rows, err := s.db.Query(`SELECT id, investigation_id, previous_status, next_status, timestamp, trigger, experiment_id, evidence_id, error FROM investigation_events WHERE investigation_id=? AND id > ? ORDER BY id`, invID, cursor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.InvestigationEvent
	for rows.Next() {
		var ev domain.InvestigationEvent
		var ts, exid, eid, errStr string
		if err := rows.Scan(&ev.ID, &ev.InvestigationID, &ev.PreviousStatus, &ev.NextStatus, &ts, &ev.Trigger, &exid, &eid, &errStr); err != nil {
			return nil, err
		}
		ev.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		ev.ExperimentID = domain.ID(exid)
		ev.EvidenceID = domain.ID(eid)
		ev.Error = errStr
		out = append(out, ev)
	}
	return out, rows.Err()
}

// Artifact persistence

// MaxArtifactSize bounds a single stored artifact file.
const MaxArtifactSize = int64(64 << 20) // 64 MB

// ArtifactRoot reports where investigation artifacts are stored.
func (s *Store) ArtifactRoot() string { return s.artifactsRoot }

// SaveArtifact writes data to an investigation-scoped file, records its
// metadata (path, size, digest) in SQLite, and returns the reference.
func (s *Store) SaveArtifact(invID domain.ID, kind string, data []byte) (domain.Artifact, error) {
	if invID == "" {
		return domain.Artifact{}, fmt.Errorf("investigation id is required")
	}
	if int64(len(data)) > MaxArtifactSize {
		return domain.Artifact{}, fmt.Errorf("artifact too large: %d bytes (max %d)", len(data), MaxArtifactSize)
	}
	dir := filepath.Join(s.artifactsRoot, string(invID))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return domain.Artifact{}, fmt.Errorf("create artifact directory: %w", err)
	}
	name := sanitizeArtifactKind(kind) + "-" + time.Now().UTC().Format("20060102T150405.000000000")
	sum := sha256.Sum256(data)
	art := domain.Artifact{
		ID:              domain.NewID(),
		InvestigationID: invID,
		Type:            kind,
		Path:            filepath.Join(string(invID), name),
		Size:            int64(len(data)),
		Digest:          hex.EncodeToString(sum[:]),
		CreatedAt:       time.Now().UTC(),
	}
	if err := os.WriteFile(filepath.Join(s.artifactsRoot, art.Path), data, 0600); err != nil {
		return domain.Artifact{}, fmt.Errorf("write artifact: %w", err)
	}
	if err := s.SaveArtifactRecord(art); err != nil {
		os.Remove(filepath.Join(s.artifactsRoot, art.Path))
		return domain.Artifact{}, fmt.Errorf("record artifact: %w", err)
	}
	slog.Info("artifact written", "investigation_id", string(invID), "type", kind, "size", art.Size)
	return art, nil
}

// ReadArtifactData reads an artifact and verifies size and digest integrity.
func (s *Store) ReadArtifactData(art domain.Artifact) ([]byte, error) {
	rel := filepath.Clean(art.Path)
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("artifact path escapes artifact root: %q", art.Path)
	}
	data, err := os.ReadFile(filepath.Join(s.artifactsRoot, rel))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxArtifactSize {
		return nil, fmt.Errorf("artifact too large: %d bytes", len(data))
	}
	if int64(len(data)) != art.Size {
		return nil, fmt.Errorf("artifact size mismatch: recorded %d, actual %d", art.Size, len(data))
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != art.Digest {
		return nil, fmt.Errorf("artifact digest mismatch: recorded %s, actual %s", art.Digest, got)
	}
	return data, nil
}

// sanitizeArtifactKind keeps artifact file names predictable and path-safe.
func sanitizeArtifactKind(kind string) string {
	if kind == "" {
		return "artifact"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(kind) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// SaveArtifactRecord saves an artifact reference to the database.
func (s *Store) SaveArtifactRecord(art domain.Artifact) error {
	slog.Debug("saving artifact record", "id", string(art.ID), "investigation_id", string(art.InvestigationID), "size", art.Size)
	_, err := s.db.Exec(
		`INSERT INTO artifacts (id, investigation_id, type, path, size, digest, created_at) VALUES (?,?,?,?,?,?,?)`,
		art.ID, art.InvestigationID, art.Type, art.Path, art.Size, art.Digest, art.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

// GetArtifact retrieves an artifact by ID.
func (s *Store) GetArtifact(id domain.ID) (domain.Artifact, error) {
	var art domain.Artifact
	var created string
	err := s.db.QueryRow(`SELECT id, investigation_id, type, path, size, digest, created_at FROM artifacts WHERE id=?`, id).Scan(
		&art.ID, &art.InvestigationID, &art.Type, &art.Path, &art.Size, &art.Digest, &created,
	)
	if err != nil {
		return art, err
	}
	art.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return art, nil
}

// ListArtifacts returns all artifacts for an investigation.
func (s *Store) ListArtifacts(invID domain.ID) ([]domain.Artifact, error) {
	rows, err := s.db.Query(`SELECT id, investigation_id, type, path, size, digest, created_at FROM artifacts WHERE investigation_id=? ORDER BY created_at`, invID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Artifact
	for rows.Next() {
		var art domain.Artifact
		var created string
		if err := rows.Scan(&art.ID, &art.InvestigationID, &art.Type, &art.Path, &art.Size, &art.Digest, &created); err != nil {
			return nil, err
		}
		art.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, art)
	}
	return out, rows.Err()
}

// DeleteArtifact removes an artifact record and its file.
func (s *Store) DeleteArtifact(id domain.ID) error {
	art, err := s.GetArtifact(id)
	if err != nil {
		return err
	}
	//Delete file, refusing references outside the artifact root
	rel := filepath.Clean(art.Path)
	if !filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		if err := os.Remove(filepath.Join(s.artifactsRoot, rel)); err != nil && !os.IsNotExist(err) {
			slog.Warn("artifact file cleanup failed", "id", string(id), "error", err)
		}
	}
	//Delete record
	_, err = s.db.Exec(`DELETE FROM artifacts WHERE id=?`, id)
	return err
}

// CleanupInvestigationArtifacts removes all artifact files and records for an investigation.
func (s *Store) CleanupInvestigationArtifacts(invID domain.ID) error {
	arts, err := s.ListArtifacts(invID)
	if err != nil {
		return err
	}
	for _, art := range arts {
		rel := filepath.Clean(art.Path)
		if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		if err := os.Remove(filepath.Join(s.artifactsRoot, rel)); err != nil && !os.IsNotExist(err) {
			slog.Warn("artifact file cleanup failed", "investigation_id", string(invID), "path", art.Path, "error", err)
		}
	}
	_, err = s.db.Exec(`DELETE FROM artifacts WHERE investigation_id=?`, invID)
	return err
}

// Schema version helpers

// CurrentSchemaVersion returns the current database schema version.
func (s *Store) CurrentSchemaVersion() (int, error) {
	return s.getSchemaVersion()
}

func (s *Store) SaveBenchmarkSuite(suite domain.BenchmarkSuite) error {
	data, err := json.Marshal(suite)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO benchmark_suites (id, version, description, data) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version, description=excluded.description, data=excluded.data`, suite.ID, suite.Version, suite.Description, string(data))
	return err
}

func (s *Store) SaveBenchmarkCase(c domain.BenchmarkCase) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO benchmark_cases (id, suite_id, version, data) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET suite_id=excluded.suite_id, version=excluded.version, data=excluded.data`, c.ID, c.SuiteID, c.Version, string(data))
	return err
}

func (s *Store) ListBenchmarkSuites() ([]domain.BenchmarkSuite, error) {
	rows, err := s.db.Query(`SELECT data FROM benchmark_suites ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.BenchmarkSuite
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var suite domain.BenchmarkSuite
		if err := json.Unmarshal([]byte(data), &suite); err != nil {
			return nil, err
		}
		out = append(out, suite)
	}
	return out, rows.Err()
}

func (s *Store) GetBenchmarkCase(id string) (domain.BenchmarkCase, error) {
	var data string
	if err := s.db.QueryRow(`SELECT data FROM benchmark_cases WHERE id=?`, id).Scan(&data); err != nil {
		return domain.BenchmarkCase{}, err
	}
	var c domain.BenchmarkCase
	return c, json.Unmarshal([]byte(data), &c)
}

func (s *Store) SaveEvaluationTrial(trial domain.EvaluationTrial) error {
	data, err := json.Marshal(trial)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO evaluation_trials (id, evaluation_id, case_id, strategy, outcome, data, started_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET outcome=excluded.outcome, data=excluded.data`, trial.ID, trial.EvaluationID, trial.CaseID, trial.Strategy, trial.Outcome, string(data), trial.StartedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) GetEvaluationTrial(id domain.ID) (domain.EvaluationTrial, error) {
	var data string
	if err := s.db.QueryRow(`SELECT data FROM evaluation_trials WHERE id=?`, id).Scan(&data); err != nil {
		return domain.EvaluationTrial{}, err
	}
	var trial domain.EvaluationTrial
	return trial, json.Unmarshal([]byte(data), &trial)
}

func (s *Store) ListEvaluationTrials(evaluationID domain.ID) ([]domain.EvaluationTrial, error) {
	rows, err := s.db.Query(`SELECT data FROM evaluation_trials WHERE evaluation_id=? ORDER BY started_at`, evaluationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.EvaluationTrial
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var trial domain.EvaluationTrial
		if err := json.Unmarshal([]byte(data), &trial); err != nil {
			return nil, err
		}
		out = append(out, trial)
	}
	return out, rows.Err()
}

func (s *Store) SaveEvaluationSummary(summary domain.EvaluationSummary) error {
	data, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO evaluation_summaries (evaluation_id, data, created_at) VALUES (?,?,?) ON CONFLICT(evaluation_id) DO UPDATE SET data=excluded.data, created_at=excluded.created_at`, summary.EvaluationID, string(data), summary.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) GetEvaluationSummary(id domain.ID) (domain.EvaluationSummary, error) {
	var data string
	if err := s.db.QueryRow(`SELECT data FROM evaluation_summaries WHERE evaluation_id=?`, id).Scan(&data); err != nil {
		return domain.EvaluationSummary{}, err
	}
	var summary domain.EvaluationSummary
	return summary, json.Unmarshal([]byte(data), &summary)
}

// Helper functions

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("marshal: %v", err))
	}
	return string(b)
}

func mustParseIDs(s string) []string {
	var out []string
	json.Unmarshal([]byte(s), &out)
	return out
}

func mustParseStrings(s string) []string {
	var out []string
	json.Unmarshal([]byte(s), &out)
	return out
}

func optTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func optTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return optTime(*t)
}
