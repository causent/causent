package mcp

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Yashbhu/Hades/internal/domain"
	"github.com/Yashbhu/Hades/internal/engine"
	"github.com/Yashbhu/Hades/internal/execution"
	"github.com/Yashbhu/Hades/internal/persistence"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	root := t.TempDir()
	store, err := persistence.Open(filepath.Join(root, "hades.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	policy := execution.Policy{AllowedCommands: map[string]bool{"python3": true}, AllowedDirs: map[string]bool{root: true}, AllowedDirPrefixes: []string{root}, AllowedEnviron: map[string]bool{}, MaxOutput: 4096}
	server, err := NewServer(Config{Store: store, Executor: execution.NewLocalExecutor(policy, execution.NewArtifactFactory(filepath.Join(root, "artifacts"))), Provider: engine.HeuristicProvider{}, AuthorizedRoots: []string{root}, AllowedCommands: policy.AllowedCommands})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestInitializeAndTools(t *testing.T) {
	server := testServer(t)
	for _, method := range []string{"initialize", "tools/list"} {
		raw := server.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"`+method+`"}`))
		var got response
		if err := json.Unmarshal(raw, &got); err != nil || got.Error != nil {
			t.Fatalf("%s: %s", method, raw)
		}
	}
	raw := server.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_investigations","arguments":{"limit":1}}}`))
	var called response
	if err := json.Unmarshal(raw, &called); err != nil || called.Error != nil {
		t.Fatalf("tools/call: %s", raw)
	}
}

func TestRejectsUnauthorizedRepository(t *testing.T) {
	server := testServer(t)
	out := server.Handle(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"start_investigation","params":{"repo":"`+os.TempDir()+`","command":["python3","-m","pytest"]}}`))
	var got response
	if json.Unmarshal(out, &got) != nil || got.Error == nil {
		t.Fatalf("expected authorization error: %s", out)
	}
}

func TestToolsRejectInvalidIDs(t *testing.T) {
	server := testServer(t)
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"get_evidence","params":{"id":"missing"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"get_investigation","params":{"id":"missing"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"verify_patch","params":{"investigation_id":"missing"}}`,
	} {
		var got response
		if err := json.Unmarshal(server.Handle(context.Background(), []byte(raw)), &got); err != nil {
			t.Fatal(err)
		}
		if got.Error == nil {
			t.Fatalf("expected structured error for %s", raw)
		}
	}
}

func makeGitStore(t *testing.T) (*Server, *persistence.Store, string) {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	store, err := persistence.Open(filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	policy := execution.Policy{AllowedCommands: map[string]bool{"python3": true}, AllowedDirs: map[string]bool{root: true}, AllowedDirPrefixes: []string{root}, AllowedEnviron: map[string]bool{}, MaxOutput: 16 << 10, Timeout: 10 * time.Second}
	server, err := NewServer(Config{Store: store, Executor: execution.NewLocalExecutor(policy, execution.NewArtifactFactory(filepath.Join(root, "artifacts"))), Provider: engine.HeuristicProvider{}, AuthorizedRoots: []string{root}, AllowedCommands: policy.AllowedCommands, MaxTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return server, store, root
}

func TestStartInvestigationPersistsAndCompletes(t *testing.T) {
	server, store, root := makeGitStore(t)
	if err := os.WriteFile(filepath.Join(root, "test_failure.py"), []byte("raise SystemExit(1)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"start_investigation","params":{"repo":"` + root + `","command":["python3","-c","raise SystemExit(1)"],"timeout":5000000000,"budget":10}}`
	var result struct {
		Result struct {
			ID string `json:"investigation_id"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal(server.Handle(context.Background(), []byte(request)), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error != nil || result.Result.ID == "" {
		t.Fatalf("start failed: %+v", result)
	}
	var inv domain.Investigation
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		inv, _ = store.GetInvestigation(domain.ID(result.Result.ID))
		if inv.Status == domain.StatusCompleted || inv.Status == domain.StatusReproFailed || inv.Status == domain.StatusExecutionFailed || inv.Status == domain.StatusCancelled {
			break
		}
	}
	if inv.ID == "" || inv.Status == domain.StatusCreated {
		t.Fatalf("investigation did not progress: %+v", inv)
	}
}

func TestCancelInvestigationUsesContext(t *testing.T) {
	server, store, root := makeGitStore(t)
	start := `{"jsonrpc":"2.0","id":1,"method":"start_investigation","params":{"repo":"` + root + `","command":["python3","-c","import time; time.sleep(10)"],"timeout":10000000000,"budget":10}}`
	var started struct {
		Result struct {
			ID string `json:"investigation_id"`
		} `json:"result"`
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal(server.Handle(context.Background(), []byte(start)), &started); err != nil || started.Error != nil {
		t.Fatalf("start failed: %v", started.Error)
	}
	cancelRequest := `{"jsonrpc":"2.0","id":2,"method":"cancel_investigation","params":{"id":"` + started.Result.ID + `"}}`
	var cancelled response
	if err := json.Unmarshal(server.Handle(context.Background(), []byte(cancelRequest)), &cancelled); err != nil || cancelled.Error != nil {
		t.Fatalf("cancel failed: %v", cancelled.Error)
	}
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		inv, getErr := store.GetInvestigation(domain.ID(started.Result.ID))
		if getErr == nil && inv.Status == domain.StatusCancelled {
			return
		}
	}
	t.Fatal("investigation did not reach cancelled state")
}
