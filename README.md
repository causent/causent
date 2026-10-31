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

## Safety properties

- patches are represented as exact structured edits;
- unknown files, hypothesis IDs, and source anchors are rejected;
- candidates are applied only in disposable workspaces;
- original and regression commands run before a patch is accepted;
- investigations and provider metadata are persisted in SQLite.

## Project layout

- `internal/engine`: investigation, evidence, model, and patch workflows
- `internal/evaluation`: reproducible benchmark runner
- `internal/execution`: bounded command execution
- `internal/persistence`: SQLite investigation and patch records
- `cmd/debug`: development CLI and evaluation commands
- `benchmarks`: versioned repair fixtures and recorded results

