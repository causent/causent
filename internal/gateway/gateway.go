// Package gateway exposes one OpenAI-compatible endpoint over several model
// providers. It deliberately keeps provider-specific wire formats here so the
// investigation engine only sees normalized chat responses.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/causent/causent/internal/domain"
	"github.com/causent/causent/internal/persistence"
)

type Config struct {
	ListenAddr      string
	Provider        string
	Model           string
	Endpoint        string
	APIKey          string
	Timeout         time.Duration
	ThinkingLevel   string
	MaxOutputTokens int
	Store           *persistence.Store
}

func ConfigFromEnvironment() Config {
	timeout := 120 * time.Second
	provider := strings.ToLower(envOr("CAUSENT_GATEWAY_PROVIDER", "ollama"))
	endpoint := os.Getenv("CAUSENT_GATEWAY_ENDPOINT")
	if endpoint == "" {
		switch provider {
		case "gemini":
			endpoint = "https://generativelanguage.googleapis.com"
		case "openai", "openai-compatible", "byok":
			endpoint = "https://api.openai.com"
		default:
			endpoint = "http://127.0.0.1:11434"
		}
	}
	apiKey := os.Getenv("CAUSENT_GATEWAY_API_KEY")
	if apiKey == "" {
		switch provider {
		case "gemini":
			apiKey = os.Getenv("GEMINI_API_KEY")
		case "openai", "openai-compatible", "byok":
			apiKey = os.Getenv("OPENAI_API_KEY")
		}
	}
	return Config{
		ListenAddr:      envOr("CAUSENT_GATEWAY_ADDR", "127.0.0.1:8787"),
		Provider:        provider,
		Model:           envOr("CAUSENT_GATEWAY_MODEL", "qwen2.5:7b"),
		Endpoint:        endpoint,
		APIKey:          apiKey,
		Timeout:         timeout,
		ThinkingLevel:   envOr("CAUSENT_GATEWAY_THINKING_LEVEL", "low"),
		MaxOutputTokens: 4096,
	}
}

type Server struct {
	config Config
	client *http.Client
}

func NewServer(config Config) *Server {
	if config.Timeout <= 0 {
		config.Timeout = 120 * time.Second
	}
	return &Server{config: config, client: &http.Client{Timeout: config.Timeout}}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/v1/models", s.models)
	mux.HandleFunc("/v1/chat/completions", s.chatCompletions)
	mux.HandleFunc("/v1/investigations/{id}/events", s.sseInvestigationEvents)
	return mux
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	server := &http.Server{Addr: s.config.ListenAddr, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
	}()
	err := server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

type chatRequest struct {
	Model          string         `json:"model"`
	Messages       []chatMessage  `json:"messages"`
	Temperature    *float64       `json:"temperature,omitempty"`
	Stream         bool           `json:"stream,omitempty"`
	ResponseFormat map[string]any `json:"response_format,omitempty"`
	MaxTokens      int            `json:"max_tokens,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index        int    `json:"index"`
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage map[string]any `json:"usage,omitempty"`
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":             "ok",
		"provider":           s.config.Provider,
		"model":              s.config.Model,
		"api_key_configured": s.config.APIKey != "",
	})
}

func (s *Server) models(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": []map[string]any{{"id": s.config.Model, "object": "model", "owned_by": s.config.Provider}}})
}

func (s *Server) chatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "only POST is supported")
		return
	}
	var request chatRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if len(request.Messages) == 0 {
		writeError(w, http.StatusBadRequest, "messages is required")
		return
	}
	if request.Stream {
		writeError(w, http.StatusNotImplemented, "streaming is not supported by this gateway version")
		return
	}
	// A gateway process has one configured upstream model. For Gemini, keep
	// that model authoritative so a stale client setting cannot consume quota
	// on a different model than the health endpoint advertises.
	if s.config.Provider == "gemini" && s.config.Model != "" {
		request.Model = s.config.Model
	} else if request.Model == "" {
		request.Model = s.config.Model
	}
	if request.MaxTokens <= 0 {
		request.MaxTokens = s.config.MaxOutputTokens
	}
	content, usage, err := s.complete(r.Context(), request)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	response := chatResponse{ID: fmt.Sprintf("causent-%d", time.Now().UnixNano()), Object: "chat.completion", Created: time.Now().Unix(), Model: request.Model, Usage: usage}
	response.Choices = append(response.Choices, struct {
		Index        int    `json:"index"`
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
	}{Index: 0, FinishReason: "stop", Message: struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{Role: "assistant", Content: content}})
	writeJSON(w, http.StatusOK, response)
}

// sseInvestigationEvents streams investigation events as Server-Sent Events.
// GET /v1/investigations/{id}/events
// Supports Last-Event-ID header for reconnection and cursor-based pagination.
// Sends heartbeat comments every 15 seconds to keep connections alive.
func (s *Server) sseInvestigationEvents(w http.ResponseWriter, r *http.Request) {
	// Guard: a gateway without a store can still serve inference, but it cannot
	// stream investigation state. Fail with a clear status instead of panicking.
	if s.config.Store == nil {
		writeError(w, http.StatusServiceUnavailable, "SSE store not configured")
		return
	}

	investigationID := ""
	if parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/"); len(parts) >= 3 {
		investigationID = parts[len(parts)-1]
	}
	if investigationID == "" {
		writeError(w, http.StatusBadRequest, "investigation ID is required")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	ctx := r.Context()

	// Last-Event-ID lets a native EventSource resume after the last event it
	// received. IDs are time-prefixed and ordered lexicographically.
	cursor := domain.ID(strings.TrimSpace(r.Header.Get("Last-Event-ID")))

	initialEvents, err := s.config.Store.ListEventsAfterCursor(domain.ID(investigationID), cursor)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list events: %v", err))
		return
	}

	// A single loop owns the response writer. Heartbeats and events are written
	// from this goroutine only, so frames can never interleave.
	pollTicker := time.NewTicker(1 * time.Second)
	defer pollTicker.Stop()
	heartbeatTicker := time.NewTicker(15 * time.Second)
	defer heartbeatTicker.Stop()

	writeEvent := func(ev domain.InvestigationEvent) bool {
		data, err := json.Marshal(map[string]any{
			"id":              string(ev.ID),
			"event":           ev.Trigger,
			"timestamp":       ev.Timestamp.UTC().Format(time.RFC3339),
			"trigger":         ev.Trigger,
			"previous_status": string(ev.PreviousStatus),
			"next_status":     string(ev.NextStatus),
			"experiment_id":   string(ev.ExperimentID),
			"evidence_id":     string(ev.EvidenceID),
			"error":           ev.Error,
		})
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: investigation_event\nid: %s\ndata: %s\n\n", ev.ID, data); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	// The cursor is the resume point, so the poll loop must start strictly after
	// it. Without this, a reconnect with no new events would replay history.
	lastSentID := cursor
	for _, ev := range initialEvents {
		if string(ev.ID) <= string(lastSentID) {
			continue
		}
		if !writeEvent(ev) {
			return
		}
		lastSentID = ev.ID
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeatTicker.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-pollTicker.C:
			events, err := s.config.Store.ListEventsAfterCursor(domain.ID(investigationID), lastSentID)
			if err != nil {
				slog.Warn("failed to list events for SSE", "investigation_id", investigationID, "error", err)
				continue
			}
			for _, ev := range events {
				if string(ev.ID) <= string(lastSentID) {
					continue
				}
				if !writeEvent(ev) {
					return
				}
				lastSentID = ev.ID
			}
		}
	}
}

func (s *Server) complete(ctx context.Context, request chatRequest) (string, map[string]any, error) {
	switch s.config.Provider {
	case "ollama":
		return s.completeOllama(ctx, request)
	case "gemini":
		return s.completeGemini(ctx, request)
	case "openai", "openai-compatible", "byok":
		return s.completeOpenAI(ctx, request)
	default:
		return "", nil, fmt.Errorf("unsupported provider %q", s.config.Provider)
	}
}

func (s *Server) completeOllama(ctx context.Context, request chatRequest) (string, map[string]any, error) {
	body := map[string]any{"model": request.Model, "messages": request.Messages, "stream": false}
	if request.ResponseFormat != nil && request.ResponseFormat["type"] == "json_schema" {
		if schema, ok := request.ResponseFormat["json_schema"].(map[string]any); ok {
			body["format"] = schema["schema"]
		}
	}
	var response struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		PromptEvalCount int `json:"prompt_eval_count"`
		EvalCount       int `json:"eval_count"`
	}
	err := s.postJSON(ctx, strings.TrimRight(s.config.Endpoint, "/")+"/api/chat", "", body, &response)
	if err != nil {
		return "", nil, err
	}
	return response.Message.Content, map[string]any{"prompt_tokens": response.PromptEvalCount, "completion_tokens": response.EvalCount}, nil
}

func (s *Server) completeOpenAI(ctx context.Context, request chatRequest) (string, map[string]any, error) {
	endpoint := strings.TrimRight(s.config.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/chat/completions") {
		endpoint += "/v1/chat/completions"
	}
	var response chatResponse
	err := s.postJSON(ctx, endpoint, s.config.APIKey, request, &response)
	if err != nil {
		return "", nil, err
	}
	if len(response.Choices) == 0 {
		return "", nil, fmt.Errorf("provider returned no choices")
	}
	return response.Choices[0].Message.Content, response.Usage, nil
}

func (s *Server) completeGemini(ctx context.Context, request chatRequest) (string, map[string]any, error) {
	parts := make([]map[string]string, 0, len(request.Messages))
	for _, message := range request.Messages {
		parts = append(parts, map[string]string{"text": message.Role + ": " + message.Content})
	}
	body := map[string]any{"contents": []any{map[string]any{"parts": parts}}}
	if request.ResponseFormat != nil {
		generation := map[string]any{"responseMimeType": "application/json"}
		if strings.HasPrefix(request.Model, "gemini-3") && s.config.ThinkingLevel != "" {
			generation["thinkingConfig"] = map[string]any{"thinkingLevel": s.config.ThinkingLevel}
		}
		if request.MaxTokens > 0 {
			generation["maxOutputTokens"] = request.MaxTokens
		}
		if schema, ok := request.ResponseFormat["json_schema"].(map[string]any); ok {
			if responseSchema, ok := schema["schema"]; ok {
				generation["responseSchema"] = responseSchema
			}
		}
		body["generationConfig"] = generation
	}
	endpoint := strings.TrimRight(s.config.Endpoint, "/")
	if !strings.Contains(endpoint, "/models/") {
		endpoint += "/v1beta/models/" + request.Model + ":generateContent"
	}
	var response struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		UsageMetadata map[string]any `json:"usageMetadata"`
	}
	err := s.postJSON(ctx, endpoint, s.config.APIKey, body, &response)
	if err != nil {
		return "", nil, err
	}
	if len(response.Candidates) == 0 || len(response.Candidates[0].Content.Parts) == 0 {
		return "", nil, fmt.Errorf("gemini returned no content")
	}
	return response.Candidates[0].Content.Parts[0].Text, response.UsageMetadata, nil
}

func (s *Server) postJSON(ctx context.Context, endpoint, apiKey string, body, output any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if apiKey != "" {
			if s.config.Provider == "gemini" {
				req.Header.Set("x-goog-api-key", apiKey)
			} else {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}
		}
		resp, err := s.client.Do(req)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if resp.StatusCode/100 == 2 {
			return json.Unmarshal(data, output)
		}
		lastErr = fmt.Errorf("upstream returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
		if !retryableStatus(resp.StatusCode) || attempt == 2 {
			return lastErr
		}
		delay := time.Duration(500*(1<<attempt)) * time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return lastErr
}

func retryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusInternalServerError || status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"message": message, "type": "gateway_error"}})
}
func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
