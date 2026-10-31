// Package mcp provides a bounded stdio JSON-RPC adapter for the Hades engine.
// It intentionally keeps MCP transport and validation separate from diagnosis.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Yashbhu/Hades/internal/domain"
	"github.com/Yashbhu/Hades/internal/engine"
	"github.com/Yashbhu/Hades/internal/execution"
	"github.com/Yashbhu/Hades/internal/persistence"
)

const (
	maxRequestBytes  = 128 << 10
	maxResponseBytes = 512 << 10
)

type Config struct {
	Store           *persistence.Store
	Executor        execution.Executor
	Provider        engine.ModelProvider
	AuthorizedRoots []string
	AllowedCommands map[string]bool
	MaxTimeout      time.Duration
	MaxBudget       int
}

type Server struct {
	cfg     Config
	mu      sync.Mutex
	running map[domain.ID]context.CancelFunc
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewServer(cfg Config) (*Server, error) {
	if cfg.Store == nil || cfg.Executor == nil || cfg.Provider == nil {
		return nil, errors.New("store, executor, and provider are required")
	}
	if cfg.MaxTimeout <= 0 {
		cfg.MaxTimeout = 10 * time.Minute
	}
	if cfg.MaxBudget <= 0 {
		cfg.MaxBudget = 100
	}
	roots := make([]string, 0, len(cfg.AuthorizedRoots))
	for _, root := range cfg.AuthorizedRoots {
		canonical, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, fmt.Errorf("authorized root %q: %w", root, err)
		}
		info, err := os.Stat(canonical)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("authorized root is not a directory: %q", root)
		}
		roots = append(roots, canonical)
	}
	cfg.AuthorizedRoots = roots
	return &Server{cfg: cfg, running: map[domain.ID]context.CancelFunc{}}, nil
}

func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	reader := bufio.NewReader(in)
	encoder := json.NewEncoder(out)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		raw, err := reader.ReadBytes('\n')
		if err != nil && len(raw) == 0 {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if len(raw) > maxRequestBytes {
			_ = encoder.Encode(response{JSONRPC: "2.0", Error: &rpcError{Code: -32600, Message: "request exceeds size limit"}})
			continue
		}
		result := s.Handle(ctx, raw)
		if len(result) > maxResponseBytes {
			result = mustJSON(response{JSONRPC: "2.0", Error: &rpcError{Code: -32603, Message: "response exceeds size limit"}})
		}
		if _, err := out.Write(append(result, '\n')); err != nil {
			return err
		}
	}
}

func (s *Server) Handle(ctx context.Context, raw []byte) []byte {
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return mustJSON(response{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "invalid JSON"}})
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return mustJSON(response{JSONRPC: "2.0", ID: rawID(req.ID), Error: &rpcError{Code: -32600, Message: "invalid JSON-RPC request"}})
	}
	result, err := s.dispatch(ctx, req.Method, req.Params)
	if err != nil {
		return mustJSON(response{JSONRPC: "2.0", ID: rawID(req.ID), Error: &rpcError{Code: -32000, Message: safeError(err)}})
	}
	return mustJSON(response{JSONRPC: "2.0", ID: rawID(req.ID), Result: result})
}

func (s *Server) dispatch(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	switch method {
	case "initialize":
		return map[string]interface{}{"protocolVersion": "2024-11-05", "capabilities": map[string]interface{}{"tools": map[string]interface{}{}}, "serverInfo": map[string]string{"name": "hades", "version": "0.8.0"}}, nil
	case "tools/list":
		return map[string]interface{}{"tools": toolDefinitions()}, nil
	case "tools/call":
		var call struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := decode(params, &call); err != nil {
			return nil, err
		}
		if call.Name == "" {
			return nil, errors.New("tool name is required")
		}
		value, err := s.dispatch(ctx, call.Name, call.Arguments)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"content": []map[string]interface{}{{"type": "text", "text": string(mustJSON(value))}}, "structuredContent": value}, nil
	case "start_investigation":
		var input struct {
			Repo    string        `json:"repo"`
			Command []string      `json:"command"`
			Timeout time.Duration `json:"timeout"`
			Budget  int           `json:"budget"`
		}
		if err := decode(params, &input); err != nil {
			return nil, err
		}
		repo, err := s.authorizeRepo(input.Repo)
		if err != nil {
			return nil, err
		}
		if len(input.Command) == 0 || !s.cfg.AllowedCommands[input.Command[0]] {
			return nil, errors.New("command executable is not authorized")
		}
		if input.Timeout <= 0 || input.Timeout > s.cfg.MaxTimeout {
			input.Timeout = s.cfg.MaxTimeout
		}
		if input.Budget <= 0 || input.Budget > s.cfg.MaxBudget {
			input.Budget = s.cfg.MaxBudget
		}
		runCtx, cancel := context.WithTimeout(context.Background(), input.Timeout)
		started := make(chan domain.Investigation, 1)
		finished := make(chan error, 1)
		investigator := &engine.Investigator{Store: s.cfg.Store, Executor: s.cfg.Executor, Provider: s.cfg.Provider}
		investigator.OnStarted = func(inv domain.Investigation) {
			s.mu.Lock()
			s.running[inv.ID] = cancel
			s.mu.Unlock()
			started <- inv
		}
		go func() {
			_, _, runErr := investigator.Investigate(runCtx, repo, input.Command, input.Timeout, input.Budget)
			finished <- runErr
		}()
		select {
		case inv := <-started:
			go func(id domain.ID) {
				<-finished
				s.mu.Lock()
				delete(s.running, id)
				s.mu.Unlock()
				cancel()
			}(inv.ID)
			return map[string]interface{}{"investigation_id": inv.ID, "status": inv.Status, "repository": repo}, nil
		case err := <-finished:
			cancel()
			if err == nil {
				return nil, errors.New("investigation completed before an ID was available")
			}
			return nil, err
		case <-ctx.Done():
			cancel()
			return nil, ctx.Err()
		}
	case "get_investigation":
		id, err := requiredID(params)
		if err != nil {
			return nil, err
		}
		return s.cfg.Store.GetInvestigation(id)
	case "list_investigations":
		var input struct {
			Limit  int `json:"limit"`
			Offset int `json:"offset"`
		}
		if err := decode(params, &input); err != nil {
			return nil, err
		}
		return s.cfg.Store.ListInvestigations(input.Limit, input.Offset)
	case "cancel_investigation":
		id, err := requiredID(params)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		cancel, ok := s.running[id]
		s.mu.Unlock()
		if !ok {
			return nil, errors.New("investigation is not running or already completed")
		}
		cancel()
		return map[string]interface{}{"status": "cancellation_requested", "investigation_id": id}, nil
	case "get_evidence":
		var input struct {
			ID            string `json:"id"`
			Investigation string `json:"investigation_id"`
		}
		if err := decode(params, &input); err != nil {
			return nil, err
		}
		id := domain.ID(input.ID)
		if id == "" {
			return nil, errors.New("id is required")
		}
		if input.Investigation != "" {
			if err := s.requireEvidenceOwnership(id, domain.ID(input.Investigation)); err != nil {
				return nil, err
			}
		}
		e, err := s.cfg.Store.GetEvidence(id)
		if err != nil {
			return nil, err
		}
		e.Payload = bounded(e.Payload, 12000)
		return e, nil
	case "list_hypotheses":
		id, err := requiredID(params)
		if err != nil {
			return nil, err
		}
		return s.cfg.Store.ListHypotheses(id)
	case "list_experiments":
		id, err := requiredID(params)
		if err != nil {
			return nil, err
		}
		return s.cfg.Store.ListExperiments(id)
	case "get_experiment":
		id, err := requiredID(params)
		if err != nil {
			return nil, err
		}
		return s.cfg.Store.GetExperiment(id)
	case "approve_experiment", "run_experiment", "cancel_experiment":
		id, err := requiredID(params)
		if err != nil {
			return nil, err
		}
		investigator := &engine.Investigator{Store: s.cfg.Store, Executor: s.cfg.Executor, Provider: s.cfg.Provider}
		switch method {
		case "approve_experiment":
			err = investigator.ApproveExperiment(ctx, id)
		case "run_experiment":
			var experiment domain.Experiment
			experiment, err = investigator.RunApprovedExperiment(ctx, id)
			if err == nil {
				return experiment, nil
			}
		case "cancel_experiment":
			err = investigator.CancelExperiment(id)
		}
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"experiment_id": id, "status": "updated"}, nil
	case "list_patches":
		id, err := requiredID(params)
		if err != nil {
			return nil, err
		}
		return s.cfg.Store.ListPatches(id)
	case "get_patch":
		id, err := requiredID(params)
		if err != nil {
			return nil, err
		}
		p, err := s.cfg.Store.GetPatch(id)
		if err != nil {
			return nil, err
		}
		p.Diff = bounded(p.Diff, 24000)
		return p, nil
	case "get_verification_report":
		id, err := requiredID(params)
		if err != nil {
			return nil, err
		}
		return s.cfg.Store.GetVerificationReport(id)
	case "verify_patch":
		var input struct {
			InvestigationID string `json:"investigation_id"`
		}
		if err := decode(params, &input); err != nil {
			return nil, err
		}
		if input.InvestigationID == "" {
			return nil, errors.New("investigation_id is required")
		}
		inv, err := s.cfg.Store.GetInvestigation(domain.ID(input.InvestigationID))
		if err != nil {
			return nil, err
		}
		rep, err := s.cfg.Store.GetReproduction(inv.ID)
		if err != nil {
			return nil, fmt.Errorf("reproduction is unavailable: %w", err)
		}
		evidence, err := s.cfg.Store.ListEvidence(inv.ID)
		if err != nil {
			return nil, err
		}
		hypotheses, err := s.cfg.Store.ListHypotheses(inv.ID)
		if err != nil {
			return nil, err
		}
		experiments, err := s.cfg.Store.ListExperiments(inv.ID)
		if err != nil {
			return nil, err
		}
		patch, err := (&engine.Investigator{Store: s.cfg.Store, Executor: s.cfg.Executor, Provider: s.cfg.Provider}).GenerateAndVerifyPatch(ctx, inv, rep, evidence, hypotheses, experiments)
		if err != nil {
			return nil, err
		}
		return patch, nil
	case "get_investigation_report":
		id, err := requiredID(params)
		if err != nil {
			return nil, err
		}
		return s.report(id)
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}

func (s *Server) authorizeRepo(path string) (string, error) {
	if path == "" || filepath.IsAbs(path) == false {
		return "", errors.New("repository must be an absolute path")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", errors.New("repository is unavailable")
	}
	info, err := os.Stat(canonical)
	if err != nil || !info.IsDir() {
		return "", errors.New("repository is not a directory")
	}
	for _, root := range s.cfg.AuthorizedRoots {
		rel, err := filepath.Rel(root, canonical)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return canonical, nil
		}
	}
	return "", errors.New("repository is outside authorized roots")
}

func (s *Server) report(id domain.ID) (map[string]interface{}, error) {
	inv, err := s.cfg.Store.GetInvestigation(id)
	if err != nil {
		return nil, err
	}
	evidence, err := s.cfg.Store.ListEvidence(id)
	if err != nil {
		return nil, err
	}
	hypotheses, err := s.cfg.Store.ListHypotheses(id)
	if err != nil {
		return nil, err
	}
	experiments, err := s.cfg.Store.ListExperiments(id)
	if err != nil {
		return nil, err
	}
	patches, err := s.cfg.Store.ListPatches(id)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"investigation": inv, "evidence": evidence, "hypotheses": hypotheses, "experiments": experiments, "patches": patches}, nil
}

func (s *Server) requireEvidenceOwnership(id, investigationID domain.ID) error {
	evidence, err := s.cfg.Store.GetEvidence(id)
	if err != nil {
		return err
	}
	if evidence.InvestigationID != investigationID {
		return errors.New("evidence does not belong to investigation")
	}
	return nil
}

func requiredID(raw json.RawMessage) (domain.ID, error) {
	var input struct {
		ID              string `json:"id"`
		InvestigationID string `json:"investigation_id"`
	}
	if err := decode(raw, &input); err != nil {
		return "", err
	}
	value := input.ID
	if value == "" {
		value = input.InvestigationID
	}
	if value == "" {
		return "", errors.New("id is required")
	}
	return domain.ID(value), nil
}

func decode(raw []byte, target interface{}) error {
	if len(raw) > maxRequestBytes {
		return errors.New("input exceeds size limit")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return errors.New("invalid tool arguments")
	}
	return nil
}
func bounded(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "...[truncated]"
}
func safeError(err error) string { return bounded(err.Error(), 500) }
func rawID(raw json.RawMessage) interface{} {
	var id interface{}
	_ = json.Unmarshal(raw, &id)
	return id
}
func mustJSON(value interface{}) []byte { data, _ := json.Marshal(value); return data }

func toolDefinitions() []map[string]interface{} {
	names := []string{"start_investigation", "get_investigation", "list_investigations", "cancel_investigation", "get_evidence", "list_hypotheses", "list_experiments", "get_experiment", "approve_experiment", "run_experiment", "cancel_experiment", "list_patches", "get_patch", "verify_patch", "get_verification_report", "get_investigation_report"}
	out := make([]map[string]interface{}, 0, len(names))
	for _, name := range names {
		schema := map[string]interface{}{"type": "object", "additionalProperties": false}
		if name == "start_investigation" {
			schema["properties"] = map[string]interface{}{"repo": map[string]string{"type": "string"}, "command": map[string]interface{}{"type": "array", "items": map[string]string{"type": "string"}}}
			schema["required"] = []string{"repo", "command"}
		} else if name == "verify_patch" {
			schema["properties"] = map[string]interface{}{"investigation_id": map[string]string{"type": "string"}}
			schema["required"] = []string{"investigation_id"}
		} else if name != "list_investigations" {
			schema["properties"] = map[string]interface{}{"id": map[string]string{"type": "string"}, "investigation_id": map[string]string{"type": "string"}}
		}
		out = append(out, map[string]interface{}{"name": name, "description": "Hades engine operation; inputs are bounded and policy-validated.", "inputSchema": schema})
	}
	return out
}
