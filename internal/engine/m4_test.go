package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/causent/causent/internal/domain"
	"github.com/causent/causent/internal/execution"
	"github.com/causent/causent/internal/persistence"
)

type fakeProvider struct {
	request ModelRequest
}

func (f *fakeProvider) Generate(_ context.Context, request ModelRequest) (ModelResponse, error) {
	f.request = request
	ids := evidenceIDs(request.Context)
	return ModelResponse{
		Metadata: domain.ModelMetadata{Provider: "fake", Model: "test"},
		Hypotheses: []ModelHypothesis{
			{Statement: "application path is broken", AffectedComponent: "application", SupportingEvidenceIDs: []string{ids[0]}, Confidence: 0.7},
			{Statement: "fixture or environment is broken", AffectedComponent: "fixture", SupportingEvidenceIDs: []string{ids[len(ids)-1]}, Confidence: 0.3},
		},
	}, nil
}

func TestM4WorkflowCollectsAndPersistsValidatedHypotheses(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	source := "def broken():\n    return 1 / 0\n\nbroken()\n"
	if err := os.WriteFile(filepath.Join(repo, "test_failure.py"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := persistence.Open(filepath.Join(t.TempDir(), "m4.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy := execution.Policy{
		AllowedCommands: map[string]bool{"python3": true},
		AllowedDirs:     map[string]bool{repo: true},
		AllowedEnviron:  map[string]bool{},
		MaxOutput:       64 * 1024,
		Timeout:         10 * time.Second,
	}
	fake := &fakeProvider{}
	investigator := &Investigator{Store: store, Executor: execution.NewLocalExecutor(policy, nil), Provider: fake}
	inv, result, err := investigator.Investigate(context.Background(), repo, []string{"python3", "test_failure.py"}, 5*time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Status != domain.StatusCompleted || result.HypothesisCount != 2 {
		t.Fatalf("status=%s hypotheses=%d", inv.Status, result.HypothesisCount)
	}
	if !strings.Contains(fake.request.Context, "EVIDENCE ") {
		t.Fatal("provider did not receive bounded evidence context")
	}
	evidence, err := store.ListEvidence(inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) < 3 {
		t.Fatalf("evidence=%d, want stack/source/git/test evidence", len(evidence))
	}
	hypotheses, err := store.ListHypotheses(inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hypotheses {
		if len(h.SupportingEvidenceIDs) == 0 || h.Provenance != "model-generated" {
			t.Fatalf("hypothesis was not evidence-linked and marked as model output: %+v", h)
		}
	}
	metadata, err := store.GetModelMetadata(inv.ID)
	if err != nil || metadata.Provider != "fake" {
		t.Fatalf("model metadata was not persisted: %+v, %v", metadata, err)
	}
}

func TestParsePythonStackTrace(t *testing.T) {
	frames := ParsePythonStackTrace(`Traceback (most recent call last):
  File "/tmp/repo/test_failure.py", line 2, in broken
    return 1 / 0
ZeroDivisionError: division by zero`)
	if len(frames) != 1 || frames[0].Line != 2 || frames[0].Function != "broken" {
		t.Fatalf("unexpected frames: %+v", frames)
	}
}
