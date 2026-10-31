package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Yashbhu/Hades/internal/domain"
)

// GatewayProvider speaks the normalized OpenAI-compatible API exposed by the
// Cypher gateway. It keeps the investigation engine independent of Gemini,
// Ollama, and other upstream wire formats.
type GatewayProvider struct {
	Endpoint string
	Model    string
	Client   *http.Client
}

type gatewayChatRequest struct {
	Model          string           `json:"model"`
	Messages       []gatewayMessage `json:"messages"`
	Temperature    float64          `json:"temperature,omitempty"`
	ResponseFormat map[string]any   `json:"response_format,omitempty"`
	MaxTokens      int              `json:"max_tokens,omitempty"`
}

type gatewayMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type gatewayChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (p GatewayProvider) endpoint() string {
	endpoint := strings.TrimRight(p.Endpoint, "/")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8787"
	}
	return endpoint + "/v1/chat/completions"
}

func (p GatewayProvider) model() string {
	if p.Model != "" {
		return p.Model
	}
	if value := os.Getenv("HADES_MODEL"); value != "" {
		return value
	}
	return "default"
}

func (p GatewayProvider) complete(ctx context.Context, prompt string, schema map[string]any) (string, error) {
	body, err := json.Marshal(gatewayChatRequest{
		Model: p.model(), Messages: []gatewayMessage{{Role: "user", Content: prompt}},
		ResponseFormat: map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "cypher_output", "strict": true, "schema": schema}},
		MaxTokens:      4096,
	})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("gateway request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return "", fmt.Errorf("gateway returned %s: %s", response.Status, strings.TrimSpace(string(data)))
	}
	var envelope gatewayChatResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&envelope); err != nil {
		return "", fmt.Errorf("decode gateway response: %w", err)
	}
	if len(envelope.Choices) == 0 {
		return "", fmt.Errorf("gateway returned no choices")
	}
	return envelope.Choices[0].Message.Content, nil
}

func (p GatewayProvider) Generate(ctx context.Context, request ModelRequest) (ModelResponse, error) {
	prompt := "Return JSON with a hypotheses array. Each item must contain statement, affected_component, supporting_evidence_ids, contradicting_evidence_ids, predicted_observations (an array of strings), confidence (0..1). Use only evidence IDs in the context. Return at least two competing hypotheses.\n\n" + request.Context
	content, err := p.complete(ctx, prompt, ollamaHypothesisSchema)
	if err != nil {
		return ModelResponse{}, err
	}
	var payload struct {
		Hypotheses []ModelHypothesis `json:"hypotheses"`
	}
	if err := json.Unmarshal([]byte(content), &payload); err != nil {
		return ModelResponse{}, fmt.Errorf("decode gateway hypotheses: %w", err)
	}
	return ModelResponse{Hypotheses: payload.Hypotheses, Metadata: domain.ModelMetadata{Provider: "gateway", Model: p.model(), Endpoint: p.endpoint()}}, nil
}

func (p GatewayProvider) GeneratePatches(ctx context.Context, request PatchRequest) ([]domain.PatchProposal, error) {
	var contextBuilder strings.Builder
	fmt.Fprintf(&contextBuilder, "INVESTIGATION %s\nREPOSITORY %s\n", request.Investigation.ID, request.Investigation.RepoPath)
	for _, ev := range request.Evidence {
		fmt.Fprintf(&contextBuilder, "EVIDENCE %s type=%s\n%s\n", ev.ID, ev.Type, bounded(ev.Payload, 4000))
	}
	for _, h := range request.Hypotheses {
		fmt.Fprintf(&contextBuilder, "HYPOTHESIS %s status=%s statement=%s\n", h.ID, h.Status, bounded(h.Statement, 1000))
	}
	validIDs := make([]string, 0, len(request.Hypotheses))
	for _, h := range request.Hypotheses {
		validIDs = append(validIDs, string(h.ID))
	}
	for _, ex := range request.Experiments {
		fmt.Fprintf(&contextBuilder, "EXPERIMENT %s evaluation=%s observation=%s\n", ex.ID, bounded(ex.Evaluation, 1000), bounded(ex.Observations, 1000))
	}
	if source, err := repositorySourceContext(request.Investigation.RepoPath); err == nil {
		contextBuilder.WriteString("REPOSITORY_SOURCE\n")
		contextBuilder.WriteString(source)
	}
	prompt := fmt.Sprintf("Return exactly one patch candidate in a patches array. Each item must contain hypothesis_ids, explanation, expected_behavior, changed_files, edits, and risks. Each edit must contain a non-empty file, non-empty old_text copied exactly from the current source, and new_text. Use exact repository-relative existing files and make old_text match the current source exactly once; do not use an empty old_text or describe an insertion without an exact source anchor. Modify the existing function or code path that caused the failure; do not add a replacement function, duplicate implementation, example, regression test, or executable test block. The patch must make the reproduced failing test pass while preserving non-target behavior. %sUse only these exact hypothesis IDs: %s. Do not invent IDs, paths, diffs, commands, markdown, or prose. Cypher will construct the unified diff.%s\n\n%s", testChangeInstruction(request.DisallowTestChanges), strings.Join(validIDs, ", "), validationFeedback(request.ValidationError), bounded(contextBuilder.String(), 16000))
	content, err := p.complete(ctx, prompt, ollamaPatchSchema)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Patches []domain.PatchProposal `json:"patches"`
	}
	if err := json.Unmarshal([]byte(content), &payload); err != nil {
		return nil, fmt.Errorf("decode gateway patches: %w", err)
	}
	for idx := range payload.Patches {
		if len(request.Hypotheses) == 0 {
			payload.Patches[idx].HypothesisIDs = nil
		}
		normalizeModelPatchPaths(&payload.Patches[idx], request.Investigation.RepoPath)
		payload.Patches[idx].Diff = ""
		payload.Patches[idx].Metadata = domain.ModelMetadata{Provider: "gateway", Model: p.model(), Endpoint: p.endpoint()}
	}
	return payload.Patches, nil
}
