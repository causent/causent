# Gap analysis: staged investigation redesign

Inspected against the current Malenia codebase (post v3 diagnostic
intelligence). This maps existing components to the required staged
architecture and records what this redesign must add.

## Existing implementation (keep and reuse)

| Area | Location | Status |
| --- | --- | --- |
| Diagnosis workflow | `internal/diagnosis` | Reproduction, classification, localization, bundles |
| Failure episode extraction | `architecture.go`, `junit.go` | Multi-failure parsing from logs / JUnit |
| Relationship grouping | `internal/relationships` | Evidence-backed related/independent groups |
| Program graph | `internal/repository` | Full revision snapshot for Go/Python/JS |
| Candidate ranking | `internal/localization` | Multi-signal scores; not causal proof |
| Competing hypotheses | `internal/reasoning` | Open-world assessment + finding validation |
| Adaptive actions | `internal/investigation`, `adaptive.go` | Budgeted action selection and durable activities |
| Persistence | `internal/persistence` | SQLite architecture records, WAL, recovery helpers |
| Isolated execution | `internal/execution` | Local/Docker with timeouts and allowlists |
| Eval corpus | `evaluation/`, `internal/evalcorpus`, `internal/evaluation` | Quality metrics and frozen cases |

## Gaps relative to the redesign

| Required capability | Gap |
| --- | --- |
| Stage 0 repository overview | Full `Analyze` walks the tree every run; no cheap reusable overview |
| Incremental indexing | `Compare` exists, but diagnosis always rebuilds a full snapshot |
| Revision-aware artifact cache | No cache abstraction; SQLite stores investigation records only |
| Staged pipeline with timings | Architecture work is one post-localization block |
| Time to first useful finding | Preliminary findings appear only after reproduce + localize + analyze + adaptive |
| Progressive report updates | Bundle/report written once at `finish`; no intermediate publication |
| Command vs investigation timeouts | Command timeouts exist; cancelled base/head runs can still leave incomplete terminal reporting |
| Stage-level metrics | No stage duration / cache hit instrumentation |
| Fast-path vs deep-path benchmarks | Diagnostic quality metrics exist; performance budgets and path comparison do not |
| Skip deep work without prerequisites | Adaptive can still run after inconclusive reproduction |

## Design decisions

1. **Reuse the existing program graph.** Extend `internal/repository` with overview and incremental update APIs rather than introducing a second indexer.
2. **Filesystem cache first.** Keys include repository identity, commit SHA, analyzer version, and artifact type. Redis is out of scope until multi-worker need is demonstrated.
3. **Repository artifacts are shareable; diagnoses are not.** Cache snapshots and overviews only. Never cache hypotheses, rankings, or conclusions as universal facts.
4. **Demand-driven stages.** Publish a preliminary diagnosis as soon as failure episodes and ranked candidates exist. Adaptive investigation is optional and budgeted.
5. **Missing index data is coverage, not negative evidence.** Incomplete graphs record limitations explicitly.

## Implementation order

1. Observability + cache + overview + incremental indexing
2. Wire staged diagnosis pipeline and progressive preliminary report
3. Timeout/cancellation hardening for partial reports
4. Performance and accuracy benchmarks for fast vs deep paths
5. Architecture documentation updates
