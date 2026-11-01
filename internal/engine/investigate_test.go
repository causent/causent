package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/causent/causent/internal/domain"
	"github.com/causent/causent/internal/execution"
	"github.com/causent/causent/internal/persistence"
)

func TestInvestigateReproducesFailure(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "test.db")
	store, err := persistence.Open(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	policy := execution.Policy{
		AllowedCommands: map[string]bool{"sh": true},
		AllowedDirs:     map[string]bool{repo: true, t.TempDir(): true},
		AllowedEnviron:  map[string]bool{},
		MaxOutput:       64 * 1024,
		Timeout:         10 * time.Second,
	}
	artifactsDir := filepath.Join(t.TempDir(), "artifacts")
	af := execution.NewArtifactFactory(artifactsDir)
	investigator := &Investigator{
		Store:    store,
		Executor: execution.NewLocalExecutor(policy, af),
	}
	inv, result, err := investigator.Investigate(
		context.Background(), repo, []string{"sh", "-c", "echo boom 1>&2; exit 7"}, 5*time.Second, 10,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Reproduction.Reproducible {
		t.Fatalf("expected reproducible, got reason=%s", result.Reproduction.Reason)
	}
	if result.Reproduction.Result.ExitCode != 7 {
		t.Fatalf("exit code = %d", result.Reproduction.Result.ExitCode)
	}
	loaded, err := store.GetInvestigation(inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != domain.StatusCompleted {
		t.Fatalf("status = %s, want %s", loaded.Status, domain.StatusCompleted)
	}
}
