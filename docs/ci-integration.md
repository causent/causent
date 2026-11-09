# CI integration

## Onboard a repository with `malenia init`

From the root of a project, run:

```sh
malenia init
```

The command reports manifest, language, package-manager, GitHub Actions, runtime,
and test-command evidence, then proposes `.malenia.yml` and
`.github/workflows/malenia.yml`. It never overwrites an existing file without
confirmation. Use `malenia init --yes` for scripted onboarding, and review the
generated `command` whenever no test command could be proven from an existing
workflow or package script.

Malenia diagnoses a failed CI run in **your** repository. Your repository keeps
its source, its CI workflow, and a small `.malenia.yml`. Malenia supplies the
diagnosis engine as a released binary, invoked through a reusable workflow.

## 1. Add `.malenia.yml`

Commit this at the repository root:

```yaml
command: go test ./...
attempts: 3
timeout: 10m
executor: local
```

`command` is the only required key. Flags and workflow inputs override it.

| Key | Meaning |
| --- | --- |
| `command` | Command that reproduces the failure |
| `base` | Base revision for the head-vs-base comparison |
| `good` | Known-good revision; enables `git bisect` |
| `attempts` | Reproduction attempts per revision (default 3) |
| `timeout` | Per-attempt timeout, Go duration (default 10m) |
| `executor` | `local` or `docker` |
| `image` | Docker image, required when `executor: docker` |
| `agent` | Ask the configured model gateway to analyze evidence |
| `probes` | Extra diagnostic commands; never modify the repository |

For a project without a toolchain on the runner, use Docker:

```yaml
command: pytest -q
executor: docker
image: python:3.12
```

## 2. Add the caller workflow

`.github/workflows/malenia.yml`:

```yaml
name: Malenia

on:
  workflow_run:
    workflows: [CI]          # name of your existing CI workflow
    types: [completed]

permissions:
  actions: read              # read the failed run's logs
  contents: read             # check out the failing commit
  pull-requests: write       # post the diagnosis on the PR

jobs:
  diagnose:
    if: |
      github.event.workflow_run.conclusion == 'failure' &&
      github.event.workflow_run.head_repository.full_name == github.repository
    uses: causent/malenia/.github/workflows/ci-diagnose.yml@v1
    with:
      run_id: ${{ github.event.workflow_run.id }}
      head_sha: ${{ github.event.workflow_run.head_sha }}
      base_ref: ${{ github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.base_sha || 'HEAD~1' }}
```

That is the whole integration. On the next failing run Malenia will:

1. check out the exact failing commit (`head_sha`, not the default branch);
2. download the failed jobs' logs with `gh run view --log-failed`;
3. include a bounded copy of the original log as separate evidence;
4. download available CI artifacts and use logs/reports as the primary evidence;
5. run the configured command against the failing commit and the exact PR base
   only when artifact evidence is insufficient;
6. write a replayable bundle and a job summary;
7. publish a bounded PR comment from a separate job when the run belongs to one.

The reusable workflow installs a pinned prebuilt Linux binary; it does not
compile Malenia. The target repository's own toolchain is only needed when a
targeted reproduction is justified. Artifact-only investigations set the
baseline source to `ci_artifact`, preserve provenance, and explicitly report
that local reproduction and revision localization were deferred.

## Inputs

All inputs are optional; `.malenia.yml` supplies the defaults.

| Input | Default | Purpose |
| --- | --- | --- |
| `command` | from `.malenia.yml` | Override the failing command |
| `head_sha` | checked-out commit | Commit to diagnose |
| `base_sha` | none | Exact base commit |
| `base_ref` | default branch | Base ref; merge-base with head is used |
| `run_id` | none | Failed run whose logs are collected |
| `attempts` | from `.malenia.yml` | Reproduction attempts |
| `docker_image` | from `.malenia.yml` | Docker executor image |
| `agent` | `false` | Model-backed analysis of collected evidence |
| `malenia_version` | `latest` | Malenia release tag to install |
| `comment` | `true` | Post the diagnosis as a PR comment |

Secrets `MALENIA_GATEWAY_ENDPOINT` and `MALENIA_GATEWAY_MODEL` are optional and
only used when `agent: true`. They are passed only to the separate trusted
analysis job, which consumes the deterministic report artifact and does not
check out or execute the target repository. Missing either secret is a clear
configuration failure when `agent: true`; no provider is contacted when it is
false.

Model analysis is not repair. It adds separately labeled model hypotheses to
the deterministic report. It does not change classification, reproduction,
refusal, or verification results. Patch generation remains a separate,
explicit `repair --model-proposals` capability.

## Manual runs

`.github/workflows/diagnosis.yml` in the Malenia repository is a
`workflow_dispatch` caller for diagnosing a known failure on demand.

## Requirements and limits

- **A Malenia release must exist.** The workflow installs
  `malenia_linux_amd64` from the Malenia GitHub releases. Publish a tag
  (`git tag v0.2.0 && git push origin v0.2.0`) before pointing a repository at
  a versioned ref. The caller's `uses:` ref (`@v0.2.0`, or a moving `@v1` tag
  you maintain) and `malenia_version` are independent: the first selects the
  workflow file, the second selects the binary.
- **Linux amd64 only.** The binary embeds SQLite through cgo, so it is built on
  the runner platform it runs on.
- **Go projects are auto-configured.** If `go.mod` exists and no Docker image is
  set, the workflow installs Go from `go-version-file`. Other languages should
  use `executor: docker` or install their toolchain in a step before calling
  the reusable workflow.
- **Execution, analysis, and publication are separate jobs.** The diagnosis job
  has no gateway secrets and disables checkout credential persistence. When
  enabled, a trusted analysis job receives only the bounded diagnosis artifact
  and gateway secrets; it does not check out or execute repository code. A
  separate publication job consumes the final report before commenting.
- **Fork pull requests are skipped by the `head_repository` guard.** Same-repo
  pull requests are also treated as untrusted during diagnosis; only the
  bounded result is exposed to the publication job.
- **The PR comment step is best-effort.** Without `pull-requests: write` the job
  summary and artifact still work.
- **Artifact-first behavior.** Failed workflow logs and downloadable artifacts
  are bounded, redacted, and parsed before reproduction. Incomplete or missing
  artifacts are recorded as limitations; they are never treated as negative
  evidence. A targeted rerun is used only when it can answer an unresolved
  question.

## Local reproduction

```sh
malenia diagnose --repo . --base origin/main
```

`malenia diagnose` reads `.malenia.yml` when flags are not supplied, and prints
the replay command for the bundle it writes.
