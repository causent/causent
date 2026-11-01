# Causent codebase guide

This document explains how the repository is structured and how a request moves through it. Read it alongside the source. Paths and names below are intentionally concrete so you can jump directly to the implementation.

## What Causent is

Causent is a language-agnostic CI failure-analysis and diagnosis system. It runs a repository command, repeats it in an isolated workspace, compares revisions, classifies the failure (PR regression, pre-existing failure, flaky test, dependency drift, or infrastructure problem), localizes likely Git history, and writes replayable evidence.

The system has two related paths:

1. **Diagnosis path:** deterministic reproduction, classification, Git localization, replay bundles, Docker execution, and SSE events.
2. **Model gateway path:** an OpenAI-compatible HTTP gateway that normalizes requests to Ollama, Gemini, or OpenAI-compatible providers. The model is optional for diagnosis.

The gateway is therefore a **provider gateway/reverse proxy for model requests**, not a general-purpose Nginx replacement. It translates the public `/v1/chat/completions` format into provider-specific formats and normalizes responses and errors.

## Repository map

```text
cmd/
  cypher/       user-facing diagnosis, replay, and repair CLI
  gateway/      starts the model gateway HTTP server
  debug/        benchmark/evaluation CLI
  mcp-server/   MCP transport for investigation capabilities

internal/
  diagnosis/    evidence-first workflow
  execution/    local and Docker command executors
  gateway/      HTTP gateway and provider adapters
  persistence/  SQLite store and schema migrations
  domain/       shared investigation and event types
  engine/       older/advanced investigation and repair engine
  evaluation/   benchmark corpus and trial execution
  config/       configuration parsing and defaults
  mcp/          MCP server implementation

benchmarks/     benchmark corpus and recorded results
.github/        CI workflow
```

## End-to-end diagnosis flow

The main entry point is `cmd/cypher/main.go`.

```text
cypher diagnose
  ↓ parse flags and build execution.Executor
diagnosis.Run
  ↓ create investigation and emit events
isolatedWorkspace
  ↓ create detached Git worktree
runOnce (N times)
  ↓ execute command through local or Docker executor
Classify
  ↓ real regression / flaky / dependency / infrastructure / refused
optional base comparison
  ↓ run the same command on --base and HEAD
localize
  ↓ known-good bisect or bounded history walk
WriteBundle
  ↓ manifest.json, events.jsonl, evidence and replay script
SQLite + SSE
  ↓ persist investigation events and stream them to clients
```

## `internal/diagnosis`

### Core types (`diagnosis.go`)

- `Classification`: the deterministic verdict enum.
- `Attempt`: one command execution, including exit code, timeout, digests, and bounded output.
- `Baseline`: aggregate results for one revision.
- `Comparison`: base revision, head revision, both baselines, and the counterfactual verdict.
- `Environment`: OS, architecture, Git revision, isolation, executor, and Docker image.
- `EvidenceItem`: a fact with an ID and bounded detail.
- `Claim`: a conclusion that cites evidence IDs.
- `Localization`: first-known-bad/last-known-good and candidate commits.
- `Report`: the final serialized diagnosis.
- `Config`: command, attempts, timeout, executor, base ref, good ref, bundle, and store settings.

### `Run`

`diagnosis.Run(ctx, Config)` is the workflow coordinator. It validates configuration, creates a persisted investigation, emits lifecycle events, reproduces the command, optionally compares `--base` against HEAD, classifies the result, localizes Git history, runs optional probes, and writes the bundle.

When `BaseRef` is set, `compare` creates a second detached worktree and uses the same executor and command. The current comparison rules are:

| Base | HEAD | Verdict |
|---|---|---|
| passes | fails deterministically | `real_regression` |
| fails | fails | `pre_existing_failure` |
| mixed outcomes on either side | any | `flaky` |
| passes | passes | `not_reproduced` |

### Classification (`classify.go`)

Classification is deliberately based on observations rather than model guesses:

- all attempts fail → deterministic failure, then inspect dependency/infrastructure signals;
- pass and fail mixed → flaky;
- all attempts pass → not reproduced;
- all attempts timeout → infrastructure/limit uncertainty.

### Git localization (`git.go`)

Git worktrees prevent diagnosis from modifying the user checkout. With `--good`, Causent verifies the good revision and performs a bounded binary search over first-parent history. Without `--good`, it walks backward looking for a passing revision.

### Bundles (`bundle.go`, `replay.go`)

A bundle is the audit artifact. It contains the report, bounded evidence, lifecycle events, environment metadata, and a replay command/script. It must not contain API keys or the full host environment.

## `internal/execution`

`execution.Executor` is the key abstraction:

```go
type Executor interface {
    Run(ctx context.Context, req Request) (Result, error)
}
```

`Request` contains command, working directory, timeout, environment, and output limits. `Result` contains exit code, stdout/stderr, duration, timeout state, and start/end timestamps.

### Local executor

Uses `os/exec`. It enforces command allowlists, allowed directories, environment policy, output limits, and context cancellation.

### Docker executor

Uses an isolated container with:

- network disabled;
- read-only root filesystem;
- writable workspace mount only;
- temporary `/tmp` tmpfs;
- dropped Linux capabilities;
- `no-new-privileges`;
- CPU, memory, and process limits;
- timeout and cancellation cleanup;
- host UID/GID mapping where supported.

Docker reduces risk but is not a perfect multi-tenant security boundary. The threat model and fixture tests should remain explicit.

## `internal/gateway`

`gateway.go` defines the HTTP service configuration and routes.

Important endpoints:

- `GET /health`: provider, model, and whether a key is configured.
- `GET /v1/models`: OpenAI-compatible model listing.
- `POST /v1/chat/completions`: normalized chat request.
- `GET /v1/investigations/{id}/events`: SSE investigation event stream.

Provider selection is controlled by environment variables:

```text
CYPHER_GATEWAY_PROVIDER=ollama|gemini|openai-compatible
CYPHER_GATEWAY_ENDPOINT=provider URL
CYPHER_GATEWAY_MODEL=model name
CYPHER_GATEWAY_API_KEY=optional key
```

Ollama is the default self-hosted path. Gemini is a hosted path. The OpenAI-compatible path can target OpenAI, Qwen-compatible services, vLLM, or other compatible endpoints.

The gateway should normalize:

- messages and roles;
- model selection;
- JSON response shape;
- errors and upstream status;
- request timeouts;
- usage metadata where available.

Provider failures such as Gemini `429` quota exhaustion or `503` high demand are upstream failures. They should be surfaced clearly rather than mistaken for diagnosis failures.

## SSE event streaming

Diagnosis events are persisted through `persistence.Store` and exposed by the gateway. Each SSE message has an event ID so clients can reconnect with `Last-Event-ID`. The stream is for progress and audit visibility; it is not the model token stream.

Model token streaming and investigation-event streaming are separate concerns:

- model streaming: tokens/chunks from `/v1/chat/completions`;
- investigation SSE: lifecycle events such as reproduction started/completed and classification completed.

## `internal/persistence`

`sqlite.go` owns the SQLite store, migrations, investigations, events, evidence, and benchmark tables. Schema migrations are versioned, but existing tables must be upgraded with `ALTER TABLE` when new columns are introduced; `CREATE TABLE IF NOT EXISTS` does not modify an existing table.

The store is used by both the CLI and gateway. `HADES_DB` selects the database path.

## `internal/domain`

Contains shared state types such as `Investigation`, statuses, event records, and IDs. Domain types should remain independent of HTTP and provider-specific details.

## `internal/evaluation`

Runs benchmark suites from `benchmarks/corpus-v1.json`, records trials in SQLite, and summarizes success, regression-free rate, root-cause accuracy, duration, and incomplete stages. Evaluation errors should distinguish tool failures (for example gateway quota) from diagnosis verdicts.

## `internal/engine`

This is the broader investigation/repair engine: evidence, experiments, model providers, patch generation, recovery, and legacy repair workflows. The diagnosis-first path is safer and more deterministic; repair remains opt-in.

## CLI commands

```bash
go run ./cmd/cypher diagnose --repo . --command "go test ./..."
go run ./cmd/cypher diagnose --repo . --base origin/main --command "go test ./..."
go run ./cmd/cypher diagnose --executor docker --image golang:1.26 --command "go test ./..."
go run ./cmd/cypher replay /path/to/bundle
go run ./cmd/debug evaluation run --corpus benchmarks/corpus-v1.json --repo .
go run ./cmd/gateway
```

## What to study next

Study the code in this order:

1. Go structs, interfaces, errors, contexts, and tests.
2. `internal/execution/executor.go` and `os/exec`.
3. `internal/diagnosis/diagnosis.go` and Git worktrees.
4. `internal/persistence/sqlite.go` and migrations.
5. `internal/gateway/gateway.go`, HTTP handlers, and SSE.
6. Docker isolation and threat modeling.
7. GitHub Actions and fork-PR permissions.
8. LLM providers, structured output, retries, quotas, and optional agent orchestration.

## Current product boundary

Causent is strongest as a language-agnostic CI diagnosis and AI-infrastructure project. The deterministic core does not require a GPU or API key. LLMs are optional for explanation, probe selection, and bounded investigation-agent behavior.

