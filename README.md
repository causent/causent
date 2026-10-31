# Cypher

Cypher is a provider-agnostic code investigation and patch verification engine.
It reproduces a failure, collects evidence, generates structured hypotheses and
patch candidates, applies candidates in disposable workspaces, and runs the
original and regression tests before accepting a patch.

The Go engine is deliberately separate from any model runtime. Ollama is the
current local provider; hosted providers and a lightweight model proxy can be
added through the `ModelProvider` and `PatchProvider` interfaces.

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

