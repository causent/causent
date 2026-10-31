package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yashbhu/Hades/internal/domain"
)

func TestOllamaGenerateUsesHypothesisSchema(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Format map[string]any `json:"format"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Format["type"] != "object" {
			t.Fatalf("format was not a JSON schema: %#v", request.Format)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":"{\"hypotheses\":[{\"statement\":\"a\",\"affected_component\":\"code\",\"supporting_evidence_ids\":[\"e1\"],\"contradicting_evidence_ids\":[],\"predicted_observations\":[\"b\"],\"confidence\":0.5},{\"statement\":\"c\",\"affected_component\":\"environment\",\"supporting_evidence_ids\":[\"e1\"],\"contradicting_evidence_ids\":[],\"predicted_observations\":[\"d\"],\"confidence\":0.2}]}"}"`))
	}))
	defer server.Close()

	response, err := (OllamaProvider{Endpoint: server.URL, Model: "test"}).Generate(context.Background(), ModelRequest{Context: "EVIDENCE e1 type=trace"})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Hypotheses) != 2 || len(response.Hypotheses[0].PredictedObservations) != 1 {
		t.Fatalf("unexpected hypotheses: %#v", response.Hypotheses)
	}
}

func TestOllamaGeneratePatchesListsExactHypothesisIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Prompt string         `json:"prompt"`
			Format map[string]any `json:"format"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}

		if request.Format["type"] != "object" ||
			!strings.Contains(request.Prompt, "only these exact hypothesis IDs: h1") ||
			!strings.Contains(request.Prompt, "Each edit must contain a non-empty file, non-empty old_text") ||
			!strings.Contains(request.Prompt, "non-empty old_text") ||
			!strings.Contains(request.Prompt, "Hades will construct the unified diff") {
			t.Fatalf("schema or IDs missing from request: %#v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":"{\"patches\":[]}"}"`))
	}))
	defer server.Close()

	_, err := (OllamaProvider{Endpoint: server.URL, Model: "test"}).GeneratePatches(context.Background(), PatchRequest{
		Hypotheses: []domain.Hypothesis{{ID: "h1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeModelPatchPaths(t *testing.T) {
	patch := domain.PatchProposal{
		ChangedFiles: []string{"/test_bug.py"},
		Diff:         "--- a//test_bug.py\n+++ b//test_bug.py\n",
	}
	normalizeModelPatchPaths(&patch, "")
	if patch.ChangedFiles[0] != "test_bug.py" {
		t.Fatalf("changed file was not normalized: %q", patch.ChangedFiles[0])
	}
	if strings.Contains(patch.Diff, "//test_bug.py") {
		t.Fatalf("diff path was not normalized: %q", patch.Diff)
	}
}

func TestNormalizeAbsoluteModelPatchPath(t *testing.T) {
	repo := t.TempDir()
	absolute := filepath.Join(repo, "bug.py")
	patch := domain.PatchProposal{
		ChangedFiles: []string{absolute},
		Diff:         "--- a//" + strings.TrimPrefix(absolute, "/") + "\n+++ b//" + strings.TrimPrefix(absolute, "/") + "\n",
	}

	normalizeModelPatchPaths(&patch, repo)
	if patch.ChangedFiles[0] != "bug.py" {
		t.Fatalf("absolute changed file was not relativized: %q", patch.ChangedFiles[0])
	}
	if strings.Contains(patch.Diff, strings.TrimPrefix(absolute, "/")) {
		t.Fatalf("absolute diff path was not normalized: %q", patch.Diff)
	}
}
