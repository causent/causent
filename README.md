# Malenia

Malenia investigates failed CI runs and produces bounded, replayable,
evidence-backed diagnosis reports. It consumes logs, JUnit reports, stack
traces, and CI artifacts before considering targeted reproduction.

When evidence is insufficient, it reproduces a failure, compares revisions
when possible, localizes relevant changes, records evidence, and classifies the
result deterministically.
Optional model-assisted analysis and repair can assist after deterministic
diagnosis, but the model never becomes the source of truth for diagnosis or
verification.

## Project status

Malenia is under active development. The GitHub Actions integration is the
primary delivery path: repositories install a reusable workflow and Malenia
supplies a pinned prebuilt binary. A hosted GitHub App is not required.

The deterministic diagnosis workflow is the primary product. Repair is
experimental and opt-in. Malenia does not silently modify a repository, create
pull requests, merge changes, or deploy anything.

Every report separates observed incidents, source-backed interpretation, causal
hypotheses, and root-cause verification. When the evidence does not establish a
mechanism, `root_cause.status` remains `unknown`, causality remains
`unverified`, and the GitHub summary says so instead of promoting candidates or
stack locations into a diagnosis.

## Requirements

Development requires:

- Go 1.26 or newer;
- Git;
- Python 3 for Python fixtures and integration tests;
- Docker only when using the Docker executor.

The default local executor is suitable for trusted local repositories. Use the
Docker executor for untrusted code when the host supports the required
container controls.

## Quick start

Run the complete test suite:

```sh
go test ./...
```

Run a deterministic diagnosis:

```sh
go run ./cmd/malenia diagnose \
  --repo . \
  --command "go test ./..."
```

The diagnosis workflow does not require a model.

To diagnose existing CI evidence without rerunning the test command when the
artifacts contain decisive failure evidence:

```sh
go run ./cmd/malenia diagnose \
  --repo . \
  --artifact-dir ./ci-artifacts \
  --artifact-first \
  --ci-log ./ci-artifacts/failure.log
```

Artifact ingestion is bounded, redacts common secret-shaped values, and records
provenance and limitations. Missing or incomplete artifacts are uncertainty,
not evidence that the failure did not occur.

Integrations can also normalize provider output and skip local execution:

```go
evidence, _ := diagnosis.ParseJUnitXML(xml, diagnosis.EvidenceProvenance{Provider: "github-actions"})
report, _ := diagnosis.DiagnoseEvidence(ctx, diagnosis.Config{RepoPath: repo}, evidence)
```

Evidence-first reports preserve workflow/job/step identity, bounded raw
provenance, parser limitations, and explicit deferred reproduction status.
Call `diagnosis.DecideReproduction(evidence, command)` before scheduling any
rerun; complete failure or pass observations defer reproduction, while timeout,
cancellation, unknown, or missing execution evidence requests a targeted
follow-up instead of an entire suite rerun.

For an offline replay of previously collected CI evidence:

```sh
malenia evidence --ci-log failed-job.log --junit test-results.xml \
  --command 'go test ./...' --output diagnosis.json
```

Run the explicit experimental repair workflow:

```sh
go run ./cmd/malenia repair \
  --repo . \
  --command "go test ./..."
```

Use Docker for repair execution:

```sh
go run ./cmd/malenia repair \
  --repo . \
  --command "go test ./..." \
  --executor docker \
  --image golang:1.26
```

The separate model proposal path is disabled by default. Enable it explicitly:

```sh
MALENIA_MODEL_PROVIDER=gateway \
MALENIA_GATEWAY_ENDPOINT=http://127.0.0.1:8787 \
MALENIA_MODEL=your-model \
go run ./cmd/malenia repair \
  --repo . \
  --command "go test ./..." \
  --model-proposals
```

The model proposal path requires a provider that implements the proposal
interface. It receives bounded diagnosis/evidence context only; it does not
receive a raw checkout or host credentials.

## Architecture

```mermaid
flowchart LR
    A[Failed CI run] --> B[Logs reports artifacts]
    B --> C[Failure extraction and grouping]
    C --> D[Targeted repository overview]
    D --> E[Preliminary diagnosis]
    E --> F{Evidence sufficient?}
    F -->|yes| G[Publish partial finding]
    F -->|no| H[Targeted reproduction and expansion]
    H --> I[Updated diagnosis]
    G --> J[Validated evidence bundle]
    I --> J
    J --> K{Optional capability}
    K -->|analysis| L[Separate trusted model analysis]
    K -->|repair| M[Patch proposal validation]
```

The model boundary is deliberately separate:

```text
deterministic diagnosis
    -> validated evidence bundle
    -> optional analysis or repair provider
    -> deterministic validation
    -> isolated execution only for repair
```

The model may propose a patch and hypotheses about that proposal. It cannot
execute commands, modify the workspace, assign diagnosis fields, or decide
whether verification succeeded.

## Diagnosis workflow

The normal workflow is:

1. Ingest bounded logs, structured reports, stack traces, and CI artifacts.
2. Extract failure episodes and group them only when evidence supports a relationship.
3. Build a cheap, revision-aware repository overview and inspect relevant code.
4. Publish a preliminary diagnosis with candidates, hypotheses, evidence, and unknowns.
5. Run targeted reproduction, revision comparison, or graph expansion only when it
   can resolve a material uncertainty.
6. Validate and persist a bounded evidence bundle with stable IDs and provenance.

When decisive CI evidence is available, artifact-first mode skips local
reproduction and revision probes for the fast path. The report marks the
baseline source as `ci_artifact` and states when localization or reproduction
was deferred. Evidence is not proof of root cause; candidates, hypotheses, and
verified causes remain separate.

Evidence-only execution also applies when reproduction is inconclusive or a
failure is not reproduced. It preserves failure evidence and publishes a
partial report without repository-wide overview, indexing, cache lookup, or
historical graph expansion. Stack frames may appear as `observed_frame`
locations; they are execution observations, not inspected source symbols or
verified root causes. Timeout-only and pass-plus-timeout executions are
classified as `inconclusive`, never as successful reproduction or proof that
the failure is absent.

Supported environment adapters currently include Go, Node.js, Python, Rust,
and Bazel. Repository-specific commands should still be reviewed explicitly.

## Optional model-assisted analysis

Malenia has three independent capabilities:

1. Deterministic diagnosis — enabled by default.
2. Model-assisted analysis — optional evidence review after diagnosis.
3. Model-generated patch proposal and verification — separately optional.

The normal GitHub Actions workflow runs deterministic diagnosis only. It does
not call a model, require gateway credentials, or expose secrets to repository
code.

For the reusable workflow, model analysis is selected explicitly:

```yaml
jobs:
  diagnose:
    uses: Malenia-org/Malenia/.github/workflows/ci-diagnose.yml@v1
    with:
      agent: true
    secrets:
      MALENIA_GATEWAY_ENDPOINT: ${{ secrets.MALENIA_GATEWAY_ENDPOINT }}
      MALENIA_GATEWAY_MODEL: ${{ secrets.MALENIA_GATEWAY_MODEL }}
```

The provider endpoint and model must both be configured when `agent: true`.
Missing configuration is an explicit error; Malenia does not silently use a
local fallback or pretend that model analysis succeeded.

The Actions flow is:

```text
CI failure
  -> deterministic diagnosis job
  -> bounded diagnosis artifact
  -> optional trusted analysis job
  -> final report and publication
```

The analysis stage receives the validated report/evidence artifact and does not
check out or execute the target repository. Fork pull requests and other
untrusted code must not receive gateway credentials. Logs, source excerpts,
commit messages, and other repository content remain untrusted data.

Model output is stored separately as model-generated hypotheses and confidence.
It cannot overwrite deterministic classification, reproduction status,
refusal status, or verification results.

When analysis is disabled, the deterministic report is produced normally and
records that no model analysis was enabled.

The diagnosis job never receives gateway credentials. When enabled, only the
separate analysis job receives them and it processes the bounded diagnosis
artifact without checking out or executing the target repository.

## Optional model-assisted repair

Repair has two provider paths:

- the existing structured patch-provider path, retained for compatibility;
- the separate opt-in `ProposalProvider` path.

The proposal path receives only a compact, validated input containing the
diagnosis, relevant evidence, failing command, focused context, and prior
validation feedback. Logs, diffs, commit messages, and source excerpts are
treated as untrusted data. Enabling analysis does not enable this path.

The proposal output is strict structured data containing:

- a unified patch;
- declared changed paths;
- rationale and limitations;
- model-generated claims with evidence IDs;
- confidence.

Evidence IDs are checked for reference integrity. A valid citation does not
prove that the claim is semantically correct.

The repair feature is disabled unless `--model-proposals` is supplied to the
repair command. Automated tests use deterministic fake providers and do not
call external model services.

## Patch safety

Before execution, Malenia validates the actual parsed patch operations. It does
not trust the model's declared paths.

Validation includes:

- normalized repository-relative paths;
- traversal and absolute-path rejection;
- binary-patch rejection;
- symlink-operation rejection;
- changed-file and changed-line limits;
- declared-path versus parsed-path comparison;
- sensitive-path restrictions;
- test-file policy checks;
- `git apply --check` before application;
- rejection reasons for every invalid proposal.

Candidate workspaces are disposable. The original repository is not modified
by patch verification.

## Execution boundary

The existing executor abstraction supports local and Docker backends.

Execution provides:

- allowlisted commands and environment variables;
- rejection of sensitive environment names;
- bounded streaming stdout/stderr retention;
- timeout and cancellation handling;
- isolated candidate workspaces;
- Docker read-only root filesystems;
- writable workspace and temporary filesystem only;
- dropped Linux capabilities;
- no-new-privileges;
- non-root container execution where configured;
- disabled Docker networking by default;
- CPU, memory, process, and output limits where supported;
- container cleanup safety nets.

The local executor is not a strong security boundary. Docker and host support
for AppArmor, rootless operation, disk quotas, swap enforcement, and precise
OOM reporting are platform-dependent and must not be assumed without runtime
verification.

## Verification contract

The hardened opt-in proposal path verifies a candidate in stages:

1. Run the original failing command repeatedly in fresh baseline workspaces.
2. Require a reproducible baseline failure.
3. Return `inconclusive` when baseline behavior is inconsistent.
4. Create a separate fresh workspace from the same revision.
5. Apply and validate the candidate patch.
6. Run the original failing command with the same execution policy.
7. Run a deterministic control-test set.
8. Persist the commands, outputs, evidence, and outcome.

Verification succeeds only when the baseline failure was reproducible, the
patched command passes, the control tests pass, and no execution or integrity
policy was violated.

Passing tests verify the reproduced behavior; they do not establish universal
correctness or root-cause certainty.

## Explicit outcomes

Repair and verification reports distinguish:

- `verified` / passed;
- `patch_rejected` / does not apply;
- `failed`;
- `timeout`;
- `inconclusive`;
- cancelled or infrastructure errors where applicable.

Reports are persisted in SQLite together with investigation events, evidence,
artifacts, patches, and verification details.

## GitHub Actions integration

### Try Malenia on a public PR without installing it in that repository

In the Malenia repository, open **Actions → Try Malenia on a public PR → Run
workflow**. Enter the target repository as `owner/name`, its open PR number, and
the test command used by that project (for example, `go test ./...` or
`npm test`). Optionally provide a Docker image containing the project's test
runtime. The workflow checks out the PR's exact head and base revisions, runs
Malenia, and attaches a diagnosis report and evidence bundle to the Actions
run. The target repository does not need a Malenia config file or workflow.

This manual trial is for public repositories and reports in the Malenia Actions
summary/artifact; it does not write a comment to the target PR. The target test
command must be supplied because Malenia cannot reliably infer the intended CI
command from a repository alone. Use the reusable workflow below for automatic
diagnosis and PR comments in a repository you control.

The reusable workflow is available at
`.github/workflows/ci-diagnose.yml`. A caller supplies the failing run and
revision:

```yaml
jobs:
  diagnose:
    if: github.event.workflow_run.conclusion == 'failure'
    uses: Malenia-org/Malenia/.github/workflows/ci-diagnose.yml@v1
    with:
      run_id: ${{ github.event.workflow_run.id }}
      head_sha: ${{ github.event.workflow_run.head_sha }}
      base_sha: ${{ github.event.workflow_run.pull_requests[0].base.sha }}
      agent: false
```

With the default `agent: false`, the workflow checks out the exact failing
commit, collects bounded failed-run logs and downloadable artifacts, and uses
that evidence before deterministic reproduction or comparison. It uploads the
evidence bundle and publishes the diagnosis when a pull request is available.
No model provider or gateway secret is required.

After the workflow connection is deployed, enable analysis by setting
`agent: true` and pass only the two dedicated gateway secrets shown above. The
analysis stage is separate from repository execution;
credentials are not passed to the failing command, Docker container, or
checked-out code. Analysis is not available for untrusted fork execution unless
the caller deliberately provides a trusted, isolated workflow boundary.

`malenia init` generates the same integration with model assistance disabled by
default. Review the generated command, revision inputs, permissions, and
secrets before committing it.

## Performance and limits

The fast path is intended to publish a useful preliminary finding within
seconds when CI artifacts are available. Cold GitHub Actions runs still include
runner startup, checkout, artifact download, and comment publication. Deep
investigation can take longer and is bounded by the configured investigation
timeout.

Malenia does not claim a root cause when evidence is insufficient. It returns a
partial or inconclusive report instead. Full-suite reruns are not the default;
reproduction is targeted and equivalent completed executions are reused only
when revision, command, and execution identity match.

`malenia diagnose` is non-mutating by default. Use `--repair` only for an
explicit bounded repair attempt. The isolated patch and its verification status
are attached to the same report and bundle; the original checkout is never
modified. A verified patch does not independently prove root cause or PR
causality.

## Configuration

Malenia supports repository configuration through `.malenia.yml` or
`.malenia.yaml`:

```yaml
command: go test ./...
attempts: 3
timeout: 10m
executor: docker
image: golang:1.26
repair:
  max_attempts: 2
```

Command-line flags take precedence. Model proposal enablement remains an
explicit command-line choice and is not enabled by repository configuration or
CI defaults.

The gateway and MCP server are separate integrations. They do not grant model
credentials to jobs that execute untrusted pull-request code.

## Evaluation

The evaluation corpus is deterministic and remains independent of optional
model providers. Cases record:

- repository and revision;
- known-good revision;
- failing command and logs;
- expected classification;
- root-cause and evidence expectations;
- verification commands.

Evaluation should measure separately:

- reproduction rate;
- classification correctness;
- evidence quality;
- proposal validity;
- patch acceptance;
- verification rate;
- regression rate;
- latency;
- model calls and token cost.

A small fixture corpus is not a general accuracy claim.

## Development and testing

Run all tests:

```sh
go test ./...
```

Run focused packages:

```sh
go test ./internal/diagnosis ./internal/execution ./internal/engine
```

The test suite includes deterministic diagnosis tests, executor policy tests,
patch validation tests, disposable-workspace tests, fake-provider tests, and
evaluation tests. External model access is not required.

Docker behavioral tests should be run on a host with Docker when validating
network, memory, process, filesystem, and cleanup controls.

## Repository layout

| Path | Contents |
| --- | --- |
| `cmd/malenia` | CLI commands and repository configuration |
| `cmd/gateway` | Local model gateway entry point |
| `internal/diagnosis` | Deterministic diagnosis, classification, localization, and bundles |
| `internal/engine` | Investigation orchestration, providers, patches, and verification |
| `internal/execution` | Local and Docker execution backends |
| `internal/domain` | Persisted investigation and report contracts |
| `internal/persistence` | SQLite state and artifact persistence |
| `internal/environment` | Repository environment adapters |
| `internal/evalcorpus` | Evaluation corpus loading and scoring |
| `evaluation/corpus` | Checked-in deterministic cases |
| `benchmarks` | Repair and model evaluation fixtures |
| `docs` | Architecture, integration, and evaluation documentation |

## Current limitations

Malenia currently does not provide:

- automatic pull-request changes or deployment;
- unrestricted network access for executed code;
- universal root-cause proof;
- exactly-once repair guarantees;
- general vector-database RAG;
- autonomous unrestricted agents;
- LLM token streaming;
- complete production token-cost telemetry;
- a full human approval UI;
- guaranteed host enforcement for platform-dependent Docker controls.

## Documentation

- [CI integration](docs/ci-integration.md) — reusable workflows, inputs,
  secrets, publication, and GitHub Actions security boundaries.
- [Runtime architecture](docs/runtime-architecture.md) — persistence, gateway,
  MCP, and event streaming architecture.
- [Diagnosis evaluation](docs/diagnosis-evaluation.md) — corpus structure,
  reproducibility, scoring, and evaluation limits.
- [Environment adapters](docs/environment-adapters.md) — supported repository
  environments and command discovery.
- [Supported environments](docs/supported-environments.md) — environment
  detection and runtime limitations.
- [External validation](docs/external-validation.md) — validation status and
  required third-party testing.
- [Installation](docs/installation.md) — installation and troubleshooting.

## License

Malenia is licensed under the Apache License 2.0. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
