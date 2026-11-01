package persistence

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/causent/causent/internal/domain"
)

func nowForTest() time.Time { return time.Now().UTC() }

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenCreatesSchemaAtVersionOne(t *testing.T) {
	s := openTestStore(t)
	version, err := s.CurrentSchemaVersion()
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if version != 4 {
		t.Fatalf("expected version 4, got %d", version)
	}
}

func TestSaveAndGetInvestigation(t *testing.T) {
	s := openTestStore(t)

	inv := domain.Investigation{
		ID:          domain.NewID(),
		RepoPath:    "/repo",
		Command:     []string{"go", "test", "./..."},
		Status:      domain.StatusCreated,
		CreatedAt:   nowForTest(),
		UpdatedAt:   nowForTest(),
		BudgetSteps: 10,
	}
	if err := s.SaveInvestigation(inv); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := s.GetInvestigation(inv.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != inv.ID || got.Status != inv.Status || got.RepoPath != inv.RepoPath {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if len(got.Command) != 3 || got.Command[0] != "go" {
		t.Fatalf("command round trip mismatch: %v", got.Command)
	}
}

func TestGetInvestigationNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.GetInvestigation("missing"); err == nil {
		t.Fatal("expected error for missing investigation")
	}
}

func TestMigrationUpgradesExistingDatabaseWithoutDataLoss(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")

	// Simulate a database created by an earlier build: tables exist, but the
	// schema_migrations table does not.
	raw, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE investigations (
		id TEXT PRIMARY KEY,
		repo_path TEXT NOT NULL,
		command TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		budget_steps INTEGER DEFAULT 0,
		budget_used INTEGER DEFAULT 0
	)`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO investigations VALUES ('legacy-1','/repo','["go","test"]','created','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',20,0)`); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	raw.Close()

	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	defer s.Close()

	got, err := s.GetInvestigation("legacy-1")
	if err != nil {
		t.Fatalf("legacy row lost: %v", err)
	}
	if got.Status != domain.StatusCreated {
		t.Fatalf("legacy status changed: %s", got.Status)
	}

	version, err := s.CurrentSchemaVersion()
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if version != 4 {
		t.Fatalf("expected version 4 after upgrade, got %d", version)
	}

	// Re-opening must be idempotent and must not drop data.
	s.Close()
	s2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if _, err := s2.GetInvestigation("legacy-1"); err != nil {
		t.Fatalf("legacy row lost on reopen: %v", err)
	}
}

func TestArtifactRecordRoundTrip(t *testing.T) {
	s := openTestStore(t)
	invID := domain.NewID()
	if err := s.SaveInvestigation(domain.Investigation{
		ID:        invID,
		RepoPath:  "/repo",
		Command:   []string{"go", "test"},
		Status:    domain.StatusCreated,
		CreatedAt: nowForTest(),
		UpdatedAt: nowForTest(),
	}); err != nil {
		t.Fatalf("save investigation: %v", err)
	}

	art := domain.Artifact{
		ID:              domain.NewID(),
		InvestigationID: invID,
		Type:            "stdout",
		Path:            filepath.Join(string(invID), "stdout.log"),
		Size:            42,
		Digest:          "abc123",
		CreatedAt:       nowForTest(),
	}
	if err := s.SaveArtifactRecord(art); err != nil {
		t.Fatalf("save artifact: %v", err)
	}

	got, err := s.GetArtifact(art.ID)
	if err != nil {
		t.Fatalf("get artifact: %v", err)
	}
	if got.Digest != art.Digest || got.Size != art.Size {
		t.Fatalf("artifact round trip mismatch: %+v", got)
	}

	list, err := s.ListArtifacts(invID)
	if err != nil {
		t.Fatalf("list artifacts: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 artifact, got %d", len(list))
	}
}

func TestListIncompleteInvestigations(t *testing.T) {
	s := openTestStore(t)
	running := domain.NewID()
	done := domain.NewID()
	for _, inv := range []domain.Investigation{
		{ID: running, RepoPath: "/r", Command: []string{"go"}, Status: domain.StatusRunningExperiment, CreatedAt: nowForTest(), UpdatedAt: nowForTest()},
		{ID: done, RepoPath: "/r", Command: []string{"go"}, Status: domain.StatusCompleted, CreatedAt: nowForTest(), UpdatedAt: nowForTest()},
	} {
		if err := s.SaveInvestigation(inv); err != nil {
			t.Fatalf("save: %v", err)
		}
	}

	incomplete, err := s.ListIncompleteInvestigations()
	if err != nil {
		t.Fatalf("list incomplete: %v", err)
	}
	if len(incomplete) != 1 || incomplete[0].ID != running {
		t.Fatalf("expected only the running investigation, got %+v", incomplete)
	}
}
