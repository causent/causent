package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yashbhu/Hades/internal/domain"
)

// ModelProvider is deliberately small so live providers and deterministic
// tests use exactly the same validation and persistence path.
type ModelProvider interface {
	Generate(ctx context.Context, request ModelRequest) (ModelResponse, error)
}

type PatchProvider interface {
	GeneratePatches(ctx context.Context, request PatchRequest) ([]domain.PatchProposal, error)
}

type PatchRequest struct {
	Investigation       domain.Investigation
	Evidence            []domain.Evidence
	Hypotheses          []domain.Hypothesis
	Experiments         []domain.Experiment
	ValidationError     string
	DisallowTestChanges bool
}

type ModelRequest struct {
	InvestigationID domain.ID
	Context         string
}

type ModelResponse struct {
	Hypotheses []ModelHypothesis
	Metadata   domain.ModelMetadata
}

type ModelHypothesis struct {
	Statement             string   `json:"statement"`
	AffectedComponent     string   `json:"affected_component"`
	SupportingEvidenceIDs []string `json:"supporting_evidence_ids"`
	ContradictingIDs      []string `json:"contradicting_evidence_ids"`
	PredictedObservations []string `json:"predicted_observations"`
	Confidence            float64  `json:"confidence"`
}

var ollamaHypothesisSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"hypotheses": map[string]any{
			"type": "array",
			"items": map[string]any{"type": "object", "properties": map[string]any{
				"statement":                  map[string]any{"type": "string"},
				"affected_component":         map[string]any{"type": "string"},
				"supporting_evidence_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"contradicting_evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"predicted_observations":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"confidence":                 map[string]any{"type": "number"},
			}, "required": []string{"statement", "affected_component", "supporting_evidence_ids", "contradicting_evidence_ids", "predicted_observations", "confidence"}},
		},
	},
	"required": []string{"hypotheses"},
}

var ollamaPatchSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"patches": map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{
			"hypothesis_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"explanation":       map[string]any{"type": "string"},
			"expected_behavior": map[string]any{"type": "string"},
			"changed_files":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"edits":             map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{"file": map[string]any{"type": "string", "minLength": 1}, "old_text": map[string]any{"type": "string", "minLength": 1}, "new_text": map[string]any{"type": "string"}}, "required": []string{"file", "old_text", "new_text"}}},
			"risks":             map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		}, "required": []string{"hypothesis_ids", "explanation", "expected_behavior", "changed_files", "edits", "risks"}}},
	},
	"required": []string{"patches"},
}

// HeuristicProvider is the offline provider used when no live endpoint is
// configured. It is deterministic and still consumes the actual evidence
// context, which keeps local investigations useful and tests credential-free.
type HeuristicProvider struct{}

func (HeuristicProvider) GeneratePatches(_ context.Context, request PatchRequest) ([]domain.PatchProposal, error) {
	for _, ev := range request.Evidence {
		for _, line := range strings.Split(ev.Payload, "\n") {
			if strings.Contains(line, "File ") && strings.Contains(line, ".py") {
				path := strings.TrimSpace(line[strings.Index(line, "File ")+len("File "):])
				path = strings.Trim(path, `"`)
				if idx := strings.Index(path, `", line`); idx >= 0 {
					path = path[:idx]
				}
				if filepath.IsAbs(path) {
					repoRoot, _ := filepath.EvalSymlinks(request.Investigation.RepoPath)
					sourcePath, _ := filepath.EvalSymlinks(path)
					if repoRoot == "" {
						repoRoot = request.Investigation.RepoPath
					}
					if sourcePath == "" {
						sourcePath = path
					}
					rel, err := filepath.Rel(repoRoot, sourcePath)
					if err != nil {
						continue
					}
					path = rel
				}
				source, err := os.ReadFile(filepath.Join(request.Investigation.RepoPath, path))
				if err != nil {
					continue
				}
				lines := strings.Split(string(source), "\n")
				for lineNo, line := range lines {
					replacement := strings.Replace(line, "1/0", "0", 1)
					if replacement == line {
						replacement = strings.Replace(line, "10 / value", "0 if value == 0 else 10 / value", 1)
					}
					if replacement == line {
						continue
					}
					diff := fmt.Sprintf("--- a/%s\n+++ b/%s\n@@ -%d +%d @@\n-%s\n+%s\n", path, path, lineNo+1, lineNo+1, line, replacement)
					return []domain.PatchProposal{{
						HypothesisIDs: hypothesisIDs(request.Hypotheses), Explanation: "Guard the failing Python division boundary against zero input.",
						ExpectedBehavior: "Zero input is handled while non-zero behavior is unchanged.", ChangedFiles: []string{filepath.ToSlash(path)},
						Diff: diff, Risks: []string{"Offline deterministic provider supports only recognized division patterns."},
						Metadata: domain.ModelMetadata{Provider: "heuristic", Model: "patch-deterministic-v1"},
					}}, nil
				}
				continue
			}
		}
	}
	return nil, fmt.Errorf("heuristic provider found no supported Python patch boundary")
}

func hypothesisIDs(hypotheses []domain.Hypothesis) []domain.ID {
	if len(hypotheses) == 0 {
		return nil
	}
	return []domain.ID{hypotheses[0].ID}
}

func (HeuristicProvider) Generate(_ context.Context, request ModelRequest) (ModelResponse, error) {
	ids := evidenceIDs(request.Context)
	if len(ids) == 0 {
		return ModelResponse{}, fmt.Errorf("model context contains no evidence references")
	}
	support := []string{ids[0]}
	if len(ids) > 1 {
		support = append(support, ids[1])
	}
	return ModelResponse{
		Metadata: domain.ModelMetadata{Provider: "heuristic", Model: "deterministic-v1"},
		Hypotheses: []ModelHypothesis{
			{Statement: "The failing execution follows a defect in the application or test code path identified by the collected trace.", AffectedComponent: "application_code", SupportingEvidenceIDs: support, PredictedObservations: []string{"The referenced frame remains failing when the test is rerun."}, Confidence: 0.62},
			{Statement: "The failure is caused by an environment, dependency, or configuration mismatch.", AffectedComponent: "environment", SupportingEvidenceIDs: []string{ids[0]}, PredictedObservations: []string{"The failure changes when the runtime or dependency configuration changes."}, Confidence: 0.24},
			{Statement: "The failure is specific to test data or a fixture rather than the general application path.", AffectedComponent: "test_or_fixture", SupportingEvidenceIDs: []string{ids[0]}, PredictedObservations: []string{"The same code path succeeds with an equivalent fixture or input."}, Confidence: 0.14},
		},
	}, nil
}

// OllamaProvider is a concrete local provider. The endpoint is local by
// default; no credentials or remote fallback are ever inferred.
type OllamaProvider struct {
	Endpoint string
	Model    string
	Client   *http.Client
}

func providerFromEnvironment() ModelProvider {
	switch strings.ToLower(os.Getenv("HADES_MODEL_PROVIDER")) {
	case "ollama":
		return OllamaProvider{Endpoint: os.Getenv("HADES_OLLAMA_ENDPOINT"), Model: os.Getenv("HADES_OLLAMA_MODEL")}
	case "gateway", "hosted", "byok", "self_hosted":
		return GatewayProvider{Endpoint: os.Getenv("HADES_GATEWAY_ENDPOINT"), Model: os.Getenv("HADES_MODEL")}
	default:
		return HeuristicProvider{}
	}
}

// ProviderFromEnvironment selects the configured provider without exposing
// credentials or provider internals to CLI callers.
func ProviderFromEnvironment() ModelProvider {
	return providerFromEnvironment()
}

func buildModelContext(inv domain.Investigation, repo string, command []string, rep domain.Reproduction, evidence []domain.Evidence) string {
	var b strings.Builder
	fmt.Fprintf(&b, "INVESTIGATION %s\nREPOSITORY %s\nCOMMAND %q\nEXIT_CODE %d\n", inv.ID, repo, command, rep.Result.ExitCode)
	for _, ev := range evidence {
		fmt.Fprintf(&b, "EVIDENCE %s type=%s source=%s digest=%s\n%s\n", ev.ID, ev.Type, ev.Source, ev.Digest, bounded(ev.Payload, 6000))
	}
	return bounded(b.String(), 24000)
}

func validateHypotheses(invID domain.ID, raw []ModelHypothesis, evidence []domain.Evidence) ([]domain.Hypothesis, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("provider returned %d hypotheses; at least two competing hypotheses are required", len(raw))
	}
	known := make(map[string]bool, len(evidence))
	for _, ev := range evidence {
		known[string(ev.ID)] = true
	}
	now := time.Now().UTC()
	out := make([]domain.Hypothesis, 0, len(raw))
	for _, candidate := range raw {
		if strings.TrimSpace(candidate.Statement) == "" || strings.TrimSpace(candidate.AffectedComponent) == "" {
			return nil, fmt.Errorf("hypothesis has empty statement or affected component")
		}
		if candidate.Confidence < 0 || candidate.Confidence > 1 {
			return nil, fmt.Errorf("hypothesis confidence %.3f is outside [0,1]", candidate.Confidence)
		}
		support := make([]domain.ID, 0, len(candidate.SupportingEvidenceIDs))
		for _, id := range candidate.SupportingEvidenceIDs {
			if !known[id] {
				return nil, fmt.Errorf("hypothesis references unknown supporting evidence %q", id)
			}
			support = append(support, domain.ID(id))
		}
		contradict := make([]domain.ID, 0, len(candidate.ContradictingIDs))
		for _, id := range candidate.ContradictingIDs {
			if !known[id] {
				return nil, fmt.Errorf("hypothesis references unknown contradicting evidence %q", id)
			}
			contradict = append(contradict, domain.ID(id))
		}
		if len(support) == 0 && len(contradict) == 0 {
			return nil, fmt.Errorf("hypothesis %q has no evidence references", candidate.Statement)
		}
		out = append(out, domain.Hypothesis{ID: newID(), InvestigationID: invID, Statement: candidate.Statement, AffectedComponent: candidate.AffectedComponent, SupportingEvidenceIDs: support, ContradictingEvidenceIDs: contradict, PredictedObservations: candidate.PredictedObservations, Confidence: candidate.Confidence, Status: domain.HypProposed, CreatedAt: now, UpdatedAt: now, Provenance: "model-generated"})
	}
	return out, nil
}

func (p OllamaProvider) Generate(ctx context.Context, request ModelRequest) (ModelResponse, error) {
	endpoint := strings.TrimRight(p.Endpoint, "/")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:11434"
	}

	model := p.Model
	if model == "" {
		model = "llama3.2"
	}
	body, err := json.Marshal(map[string]any{
		"model": model, "stream": false, "format": ollamaHypothesisSchema,
		"prompt": "Return JSON with a hypotheses array. Each item must contain statement, affected_component, supporting_evidence_ids, contradicting_evidence_ids, predicted_observations (an array of strings), confidence (0..1). Use only evidence IDs in the context. Return at least two competing hypotheses.\n\n" + request.Context,
	})
	if err != nil {
		return ModelResponse{}, err
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return ModelResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		return ModelResponse{}, fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return ModelResponse{}, fmt.Errorf("ollama returned %s", resp.Status)
	}
	var envelope struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return ModelResponse{}, fmt.Errorf("decode ollama response: %w", err)
	}
	var payload struct {
		Hypotheses []ModelHypothesis `json:"hypotheses"`
	}
	if err := json.Unmarshal([]byte(envelope.Response), &payload); err != nil {
		return ModelResponse{}, fmt.Errorf("decode structured hypotheses: %w", err)
	}
	return ModelResponse{Hypotheses: payload.Hypotheses, Metadata: domain.ModelMetadata{Provider: "ollama", Model: model, Endpoint: endpoint}}, nil
}

func (p OllamaProvider) GeneratePatches(ctx context.Context, request PatchRequest) ([]domain.PatchProposal, error) {
	endpoint := strings.TrimRight(p.Endpoint, "/")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:11434"
	}
	model := p.Model
	if model == "" {
		model = "llama3.2"
	}
	var contextBuilder strings.Builder
	fmt.Fprintf(&contextBuilder, "INVESTIGATION %s\nREPOSITORY %s\n", request.Investigation.ID, request.Investigation.RepoPath)
	for _, ev := range request.Evidence {
		fmt.Fprintf(&contextBuilder, "EVIDENCE %s type=%s\n%s\n", ev.ID, ev.Type, bounded(ev.Payload, 4000))
	}
	for _, h := range request.Hypotheses {
		fmt.Fprintf(&contextBuilder, "HYPOTHESIS %s status=%s statement=%s\n", h.ID, h.Status, bounded(h.Statement, 1000))
	}
	validHypothesisIDs := make([]string, 0, len(request.Hypotheses))
	for _, h := range request.Hypotheses {
		validHypothesisIDs = append(validHypothesisIDs, string(h.ID))
	}
	for _, ex := range request.Experiments {
		fmt.Fprintf(&contextBuilder, "EXPERIMENT %s evaluation=%s observation=%s\n", ex.ID, bounded(ex.Evaluation, 1000), bounded(ex.Observations, 1000))
	}
	if source, err := repositorySourceContext(request.Investigation.RepoPath); err == nil {
		contextBuilder.WriteString("REPOSITORY_SOURCE\n")
		contextBuilder.WriteString(source)
	}
	body, err := json.Marshal(map[string]any{
		"model": model, "stream": false, "format": ollamaPatchSchema,
		"prompt": fmt.Sprintf("Return JSON with a patches array. Each item must contain hypothesis_ids, explanation, expected_behavior, changed_files, edits, and risks. Each edit must contain a non-empty file, non-empty old_text copied exactly from the current source, and new_text. Use exact repository-relative existing files and make old_text match the current source exactly once; do not use an empty old_text or describe an insertion without an exact source anchor. Modify the existing function or code path that caused the failure; do not add a replacement function, duplicate implementation, example, regression test, or executable test block. The patch must make the reproduced failing test pass while preserving non-target behavior. %sUse only these exact hypothesis IDs: %s. Do not invent IDs, paths, diffs, commands, markdown, or prose. Hades will construct the unified diff.%s\n\n%s", testChangeInstruction(request.DisallowTestChanges), strings.Join(validHypothesisIDs, ", "), validationFeedback(request.ValidationError), bounded(contextBuilder.String(), 24000)),
	})
	if err != nil {
		return nil, err
	}

	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama patch request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("ollama returned %s", resp.Status)
	}
	var envelope struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 512<<10)).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode ollama patch response: %w", err)
	}
	var payload struct {
		Patches []domain.PatchProposal `json:"patches"`
	}
	if err := json.Unmarshal([]byte(envelope.Response), &payload); err != nil {
		return nil, fmt.Errorf("decode structured patches: %w", err)
	}
	for idx := range payload.Patches {
		if len(request.Hypotheses) == 0 {
			payload.Patches[idx].HypothesisIDs = nil
		}
		normalizeModelPatchPaths(&payload.Patches[idx], request.Investigation.RepoPath)
		if payload.Patches[idx].Diff != "" {
			payload.Patches[idx].Diff = ""
		}
		payload.Patches[idx].Metadata = domain.ModelMetadata{Provider: "ollama", Model: model, Endpoint: endpoint}
	}
	return payload.Patches, nil
}

func validationFeedback(message string) string {
	if strings.TrimSpace(message) == "" {
		return ""
	}

	return "\nThe previous proposal was rejected by Hades: " + bounded(message, 1000) + ". Correct that specific issue."
}

func testChangeInstruction(disallow bool) string {
	if disallow {
		return "Do not modify test files; repair the implementation under test. The failing test is only a specification. Follow its imports and edit the existing imported implementation function in a non-test source file. "
	}
	return ""
}

func repositorySourceContext(repo string) (string, error) {
	var b strings.Builder
	count := 0
	err := filepath.Walk(repo, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || strings.HasPrefix(info.Name(), "__") {
				return filepath.SkipDir
			}
			return nil
		}
		if count >= 8 || filepath.Ext(path) != ".py" {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		rel, relErr := filepath.Rel(repo, path)
		if relErr != nil {
			return nil
		}
		b.WriteString("\n--- " + filepath.ToSlash(rel) + " ---\n")
		b.WriteString(bounded(string(data), 2500))
		count++
		return nil
	})
	return bounded(b.String(), 8000), err
}

// Models occasionally render repository-relative paths with one leading slash.
// Normalize only that unambiguous presentation error; traversal and absolute
// paths remain subject to validatePatchProposal.
func normalizeModelPatchPaths(patch *domain.PatchProposal, repoPath string) {
	for idx, file := range patch.ChangedFiles {
		if strings.HasPrefix(file, "/") && !strings.HasPrefix(file, "//") {
			relative := strings.TrimPrefix(file, "/")
			if repoPath != "" {
				if candidate, err := filepath.Rel(repoPath, file); err == nil && candidate != ".." && !strings.HasPrefix(candidate, ".."+string(filepath.Separator)) {
					relative = candidate
				}
			}
			patch.ChangedFiles[idx] = filepath.ToSlash(relative)
		}
	}
	for _, file := range patch.ChangedFiles {
		normalized := filepath.ToSlash(file)
		patch.Diff = strings.ReplaceAll(patch.Diff, "a//"+normalized, "a/"+normalized)
		patch.Diff = strings.ReplaceAll(patch.Diff, "b//"+normalized, "b/"+normalized)
		if repoPath != "" {
			absolute := filepath.Join(repoPath, filepath.FromSlash(normalized))
			if resolved, err := filepath.Rel(repoPath, absolute); err == nil {
				resolved = filepath.ToSlash(resolved)
				patch.Diff = strings.ReplaceAll(patch.Diff, "a/"+absolute, "a/"+resolved)
				patch.Diff = strings.ReplaceAll(patch.Diff, "b/"+absolute, "b/"+resolved)
				patch.Diff = strings.ReplaceAll(patch.Diff, "a//"+strings.TrimPrefix(absolute, "/"), "a/"+resolved)
				patch.Diff = strings.ReplaceAll(patch.Diff, "b//"+strings.TrimPrefix(absolute, "/"), "b/"+resolved)
			}
		}
	}
}

func evidenceIDs(context string) []string {
	var ids []string
	for _, line := range strings.Split(context, "\n") {
		if strings.HasPrefix(line, "EVIDENCE ") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				ids = append(ids, parts[1])
			}
		}
	}
	return ids
}
