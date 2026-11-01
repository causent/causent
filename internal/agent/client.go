package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Evidence struct{ ID, Kind, Detail string }
type Input struct {
	Classification string
	Command        []string
	Evidence       []Evidence
}
type Hypothesis struct {
	Statement   string   `json:"statement"`
	Component   string   `json:"affected_component"`
	EvidenceIDs []string `json:"supporting_evidence_ids"`
	Confidence  float64  `json:"confidence"`
}
type Report struct {
	Provider   string       `json:"provider"`
	Model      string       `json:"model"`
	Hypotheses []Hypothesis `json:"hypotheses"`
}
type Client struct {
	Endpoint, Model string
	HTTP            *http.Client
}

const maxHypotheses = 12

// ValidateReport enforces the boundary contract independently of the provider.
// A model may propose interpretations, but it may not create evidence.
func ValidateReport(out Report, evidence []Evidence) error {
	known := map[string]bool{}
	for _, e := range evidence {
		if strings.TrimSpace(e.ID) == "" {
			return fmt.Errorf("evidence has empty ID")
		}
		known[e.ID] = true
	}
	if len(out.Hypotheses) > maxHypotheses {
		return fmt.Errorf("too many hypotheses: %d", len(out.Hypotheses))
	}
	for i, h := range out.Hypotheses {
		if strings.TrimSpace(h.Statement) == "" {
			return fmt.Errorf("hypothesis %d has empty statement", i)
		}
		if h.Confidence < 0 || h.Confidence > 1 {
			return fmt.Errorf("hypothesis %d confidence outside [0,1]", i)
		}
		seen := map[string]bool{}
		for _, id := range h.EvidenceIDs {
			if !known[id] {
				return fmt.Errorf("agent returned unknown evidence ID %q", id)
			}
			if seen[id] {
				return fmt.Errorf("hypothesis %d repeats evidence ID %q", i, id)
			}
			seen[id] = true
		}
	}
	return nil
}

func (c *Client) Analyze(ctx context.Context, in Input) (Report, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "Analyze this CI failure. The deterministic classification is %s. Command: %s\n", in.Classification, strings.Join(in.Command, " "))
	b.WriteString("Use only the evidence IDs provided. Return JSON with hypotheses, each containing statement, affected_component, supporting_evidence_ids, and confidence from 0 to 1. Do not invent evidence IDs.\n")
	for _, e := range in.Evidence {
		fmt.Fprintf(&b, "EVIDENCE %s [%s]\n%s\n", e.ID, e.Kind, redact(e.Detail))
	}
	// Supplying a JSON schema makes the gateway apply provider-specific output
	// limits and low-thinking settings for Gemini, while keeping the result
	// machine-validated across all providers.
	var body []byte
	body, _ = json.Marshal(map[string]any{
		"model": c.Model, "messages": []map[string]string{{"role": "user", "content": b.String()}},
		"temperature": 0, "max_tokens": 512,
		"response_format": map[string]any{"type": "json_schema", "json_schema": map[string]any{
			"name": "agent_report", "strict": true, "schema": map[string]any{
				"type": "object", "properties": map[string]any{"hypotheses": map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{
					"statement": map[string]any{"type": "string"}, "affected_component": map[string]any{"type": "string"},
					"supporting_evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "confidence": map[string]any{"type": "number"},
				}, "required": []string{"statement", "affected_component", "supporting_evidence_ids", "confidence"}}}},
				"required": []string{"hypotheses"},
			},
		}},
	})
	endpoint := strings.TrimRight(c.Endpoint, "/") + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Report{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	h := c.HTTP
	if h == nil {
		h = &http.Client{Timeout: 120 * time.Second}
	}
	res, err := h.Do(req)
	if err != nil {
		return Report{}, fmt.Errorf("agent gateway request: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		data, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return Report{}, fmt.Errorf("agent gateway returned %s: %s", res.Status, strings.TrimSpace(string(data)))
	}
	var envelope struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&envelope); err != nil {
		return Report{}, err
	}
	if len(envelope.Choices) == 0 {
		return Report{}, fmt.Errorf("agent gateway returned no choices")
	}
	var out Report
	if err := json.Unmarshal([]byte(envelope.Choices[0].Message.Content), &out); err != nil {
		return Report{}, fmt.Errorf("decode agent JSON: %w", err)
	}
	out.Provider = "gateway"
	out.Model = envelope.Model
	if err := ValidateReport(out, in.Evidence); err != nil {
		return Report{}, err
	}
	return out, nil
}

func redact(s string) string {
	for _, key := range []string{"AWS_SECRET_ACCESS_KEY=", "GITHUB_TOKEN=", "CAUSENT_GATEWAY_API_KEY="} {
		for {
			i := strings.Index(s, key)
			if i < 0 {
				break
			}
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				end = len(s) - i
			}
			s = s[:i] + key + "[REDACTED]" + s[i+end:]
		}
	}
	return s
}
