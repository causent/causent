package persistence

import (
	"encoding/json"
	"github.com/causent/malenia/internal/domain"
	"time"
)

func (s *Store) saveArchitecture(kind, id string, investigationID domain.ID, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO architecture_records(id,kind,investigation_id,data,created_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, id, kind, nullableID(investigationID), string(b), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func nullableID(id domain.ID) any {
	if id == "" {
		return nil
	}
	return string(id)
}

func (s *Store) SaveRepository(v domain.Repository) error {
	return s.saveArchitecture("repository", v.ID, "", v)
}
func (s *Store) SaveRevision(v domain.Revision) error {
	return s.saveArchitecture("revision", v.ID, "", v)
}
func (s *Store) SavePullRequest(v domain.PullRequest) error {
	return s.saveArchitecture("pull_request", v.ID, "", v)
}
func (s *Store) SaveCIExecution(v domain.CIExecution) error {
	return s.saveArchitecture("ci_execution", v.ID, "", v)
}
func (s *Store) SaveFailureEpisode(v domain.FailureEpisode) error {
	return s.saveArchitecture("failure_episode", v.ID, "", v)
}
func (s *Store) SaveCodeLocation(v domain.CodeLocation) error {
	return s.saveArchitecture("code_location", v.ID, "", v)
}
func (s *Store) SaveProgramNode(v domain.ProgramNode) error {
	return s.saveArchitecture("program_node", v.ID, "", v)
}

// SaveProgramNodes persists an indexed snapshot in one transaction. Large
// repositories make one SQLite transaction per node prohibitively expensive.
func (s *Store) SaveProgramNodes(values []domain.ProgramNode) error {
	return s.saveArchitectureBatch("program_node", values)
}

func (s *Store) saveArchitectureBatch(kind string, values []domain.ProgramNode) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO architecture_records(id,kind,investigation_id,data,created_at) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, value := range values {
		b, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			_ = tx.Rollback()
			return marshalErr
		}
		if _, err := stmt.Exec(value.ID, kind, nil, string(b), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) SaveCodeDelta(v domain.CodeDelta) error {
	return s.saveArchitecture("code_delta", v.ID, "", v)
}
func (s *Store) SaveExecutionPath(v domain.ExecutionPath) error {
	return s.saveArchitecture("execution_path", v.ID, v.InvestigationID, v)
}
func (s *Store) SaveCandidate(v domain.CandidateLocation) error {
	return s.saveArchitecture("candidate", v.ID, v.InvestigationID, v)
}
func (s *Store) SaveFailureGroup(v domain.FailureGroup) error {
	return s.saveArchitecture("failure_group", v.ID, v.InvestigationID, v)
}
func (s *Store) SaveFinding(v domain.DiagnosticFinding) error {
	return s.saveArchitecture("finding", v.ID, v.InvestigationID, v)
}
func (s *Store) SaveActivity(v domain.Activity) error {
	return s.saveArchitecture("activity", v.ID, v.InvestigationID, v)
}

func (s *Store) SaveAdaptiveState(v domain.AdaptiveState) error {
	return s.saveArchitecture("adaptive_state", "adaptive:"+string(v.InvestigationID), v.InvestigationID, v)
}

func (s *Store) GetAdaptiveState(id domain.ID) (domain.AdaptiveState, error) {
	var value domain.AdaptiveState
	err := s.GetArchitecture("adaptive_state", "adaptive:"+string(id), &value)
	return value, err
}

func (s *Store) SaveRelationship(v domain.Relationship) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO architecture_relationships(id,investigation_id,source_type,source_id,target_type,target_id,relationship_type,revision_id,evidence_ids,data,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,evidence_ids=excluded.evidence_ids`, v.ID, nullableID(v.InvestigationID), v.SourceType, v.SourceID, v.TargetType, v.TargetID, v.Type, v.RevisionID, mustJSON(v.EvidenceIDs), string(b), v.CreatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

// SaveRelationships persists graph edges in one transaction.
func (s *Store) SaveRelationships(values []domain.Relationship) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO architecture_relationships(id,investigation_id,source_type,source_id,target_type,target_id,relationship_type,revision_id,evidence_ids,data,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data,evidence_ids=excluded.evidence_ids`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, value := range values {
		b, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			_ = tx.Rollback()
			return marshalErr
		}
		if _, err := stmt.Exec(value.ID, nullableID(value.InvestigationID), value.SourceType, value.SourceID, value.TargetType, value.TargetID, value.Type, value.RevisionID, mustJSON(value.EvidenceIDs), string(b), value.CreatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SaveClaimValidation(v domain.ClaimValidation) error {
	_, err := s.db.Exec(`INSERT INTO claim_validations(claim_id,valid,reasons,validated_at) VALUES(?,?,?,?) ON CONFLICT(claim_id) DO UPDATE SET valid=excluded.valid,reasons=excluded.reasons,validated_at=excluded.validated_at`, v.ClaimID, boolInt(v.Valid), mustJSON(v.Reasons), v.ValidatedAt.UTC().Format(time.RFC3339Nano))
	return err
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *Store) GetArchitecture(kind, id string, dst any) error {
	var data string
	err := s.db.QueryRow(`SELECT data FROM architecture_records WHERE kind=? AND id=?`, kind, id).Scan(&data)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(data), dst)
}

func (s *Store) ListArchitecture(kind string, investigationID domain.ID, dst func([]byte) error) error {
	rows, err := s.db.Query(`SELECT data FROM architecture_records WHERE kind=? AND (?='' OR investigation_id=?) ORDER BY created_at`, kind, string(investigationID), string(investigationID))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return err
		}
		if err := dst(data); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Store) ListRelationships(investigationID domain.ID) ([]domain.Relationship, error) {
	rows, err := s.db.Query(`SELECT data FROM architecture_relationships WHERE (?='' OR investigation_id=?) ORDER BY created_at`, string(investigationID), string(investigationID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Relationship
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var v domain.Relationship
		if err := json.Unmarshal([]byte(data), &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) ListActivities(investigationID domain.ID) ([]domain.Activity, error) {
	var out []domain.Activity
	err := s.ListArchitecture("activity", investigationID, func(data []byte) error {
		var value domain.Activity
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		out = append(out, value)
		return nil
	})
	return out, err
}

func (s *Store) ListFailureGroups(investigationID domain.ID) ([]domain.FailureGroup, error) {
	var out []domain.FailureGroup
	err := s.ListArchitecture("failure_group", investigationID, func(data []byte) error {
		var value domain.FailureGroup
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		out = append(out, value)
		return nil
	})
	return out, err
}
