# Cypher

Cypher is a provider-agnostic code investigation and patch verification engine.
It reproduces a failure, collects evidence, generates structured hypotheses and
patch candidates, applies candidates in disposable workspaces, and runs the
original and regression tests before accepting a patch.

The Go engine is deliberately separate from any model runtime. Ollama is the
current local provider; hosted providers and a lightweight model proxy can be
added through the `ModelProvider` and `PatchProvider` interfaces.

## Inference gateway

Cypher includes a small OpenAI-compatible gateway. It normalizes Ollama,
Gemini, and OpenAI-compatible endpoints so the repair engine does not depend on
provider-specific request formats.

Start it with Ollama:

```sh
CYPHER_GATEWAY_PROVIDER=ollama \
CYPHER_GATEWAY_MODEL=qwen2.5:7b \
go run ./cmd/gateway
```

Start it with Gemini:

```sh
GEMINI_API_KEY=... \
CYPHER_GATEWAY_PROVIDER=gemini \
CYPHER_GATEWAY_MODEL=gemini-3.8-flash \
go run ./cmd/gateway
```

Then select the gateway from the Go engine:

```sh
HADES_MODEL_PROVIDER=gateway \
HADES_GATEWAY_ENDPOINT=http://127.0.0.1:8787 \
HADES_MODEL=gemini-3.8-flash \
go run ./cmd/debug evaluation run \
  --corpus benchmarks/corpus-v1.json --repo "$PWD" \
  --db /tmp/cypher-gemini.db --strategy direct_repair \
  --timeout 5m --budget 20
```

The gateway is a local routing component in this repository. A hosted Cypher
inference service, quotas, authentication, and billing are separate deployment
work that should be added only after the provider and patch benchmarks are
stable. Do not expose this development gateway publicly without adding
authentication and request limits.

## Requirements

- Go 1.26 or newer (see `go.mod`)
- a C toolchain: persistence uses `mattn/go-sqlite3` through cgo
- Docker, only if you intend to run `DockerExecutor`

## Quick start

```sh
go test ./...
go run ./cmd/debug evaluation run \
  --corpus benchmarks/corpus-v1.json \
  --repo "$PWD" \
  --db /tmp/cypher-evaluation.db \
  --strategy direct_repair,evidence_guided \
  --timeout 5m --budget 20
```

The seed corpus currently contains deterministic Python repair fixtures. The
evaluation engine is intended to expand to Go, JavaScript/TypeScript, Rust, and
other repository test commands.

## Testing

Unit tests hit no network and need no model runtime:

```sh
go test -race -shuffle=on -count=1 ./...
go vet ./...
```

`HADES_MODEL_PROVIDER` selects the provider for anything that generates
hypotheses. Leave it unset to use the deterministic heuristic provider; setting
it to `ollama` or `gateway` makes those tests require a reachable model server.
CI runs with no provider variables set, so tests must not depend on them.

Docker-backed execution is not yet wired into the engine. When it is, tests
that need a daemon belong behind a build tag and must skip when `docker info`
fails.

## Safety properties

- patches are represented as exact structured edits;
- unknown files, hypothesis IDs, and source anchors are rejected;
- candidates are applied only in disposable workspaces;
- original and regression commands run before a patch is accepted;
- investigations and provider metadata are persisted in SQLite.

`DockerExecutor` is the container path: no network, read-only root filesystem
with a tmpfs for scratch, all capabilities dropped, and memory/CPU/pid limits
applied. It requires `CollectPolicy.Image` and is not yet used by the
investigator, which still runs commands on the host through `LocalExecutor`
under an allow-list policy.

## Project layout

- `internal/engine`: investigation, evidence, model, and patch workflows
- `internal/evaluation`: reproducible benchmark runner
- `internal/execution`: bounded command execution, local and container
- `internal/gateway`: OpenAI-compatible gateway
- `internal/mcp`: MCP server for investigations, evidence, and artifacts
- `internal/persistence`: SQLite investigation and patch records
- `cmd/debug`: development CLI and evaluation commands
- `cmd/gateway`: inference gateway
- `cmd/mcp-server`: MCP server entrypoint
- `benchmarks`: versioned repair fixtures and recorded results


