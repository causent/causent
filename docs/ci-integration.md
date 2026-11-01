# CI integration

## Onboard a repository with `causent init`

From the root of a project, run:

```sh
causent init
```

The command reports manifest, language, package-manager, GitHub Actions, runtime,
and test-command evidence, then proposes `.causent.yml` and
`.github/workflows/causent.yml`. It never overwrites an existing file without
confirmation. Use `causent init --yes` for scripted onboarding, and review the
generated `command` whenever no test command could be proven from an existing
workflow or package script.

Causent diagnoses a failed CI run in **your** repository. Your repository keeps
its source, its CI workflow, and a small `.causent.yml`. Causent supplies the
diagnosis engine as a released binary, invoked through a reusable workflow.

## 1. Add `.causent.yml`

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

`.github/workflows/causent.yml`:

```yaml
name: Causent

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
    uses: causent/causent/.github/workflows/ci-diagnose.yml@v1
    with:
      run_id: ${{ github.event.workflow_run.id }}
      head_sha: ${{ github.event.workflow_run.head_sha }}
      base_ref: ${{ github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.base_sha || 'HEAD~1' }}
```

That is the whole integration. On the next failing run Causent will:

1. check out the exact failing commit (`head_sha`, not the default branch);
2. download the failed jobs' logs with `gh run view --log-failed`;
3. include a bounded copy of the original log as separate evidence;
4. run the configured command against the failing commit and the exact PR base;
5. write a replayable bundle and a job summary;
6. publish a bounded PR comment from a separate job when the run belongs to one.

## Inputs

All inputs are optional; `.causent.yml` supplies the defaults.

| Input | Default | Purpose |
| --- | --- | --- |
| `command` | from `.causent.yml` | Override the failing command |
| `head_sha` | checked-out commit | Commit to diagnose |
| `base_sha` | none | Exact base commit |
| `base_ref` | default branch | Base ref; merge-base with head is used |
| `run_id` | none | Failed run whose logs are collected |
| `attempts` | from `.causent.yml` | Reproduction attempts |
| `docker_image` | from `.causent.yml` | Docker executor image |
| `agent` | `false` | Model-backed analysis of collected evidence |
| `causent_version` | `latest` | Causent release tag to install |
| `comment` | `true` | Post the diagnosis as a PR comment |

Secrets `CAUSENT_GATEWAY_ENDPOINT` and `CAUSENT_GATEWAY_MODEL` are optional and
only used when `agent: true`.

## Manual runs

`.github/workflows/diagnosis.yml` in the Causent repository is a
`workflow_dispatch` caller for diagnosing a known failure on demand.

## Requirements and limits

- **A Causent release must exist.** The workflow installs
  `causent_linux_amd64` from the Causent GitHub releases. Publish a tag
  (`git tag v0.2.0 && git push origin v0.2.0`) before pointing a repository at
  a versioned ref. The caller's `uses:` ref (`@v0.2.0`, or a moving `@v1` tag
  you maintain) and `causent_version` are independent: the first selects the
  workflow file, the second selects the binary.
- **Linux amd64 only.** The binary embeds SQLite through cgo, so it is built on
  the runner platform it runs on.
- **Go projects are auto-configured.** If `go.mod` exists and no Docker image is
  set, the workflow installs Go from `go-version-file`. Other languages should
  use `executor: docker` or install their toolchain in a step before calling
  the reusable workflow.
- **Execution and publication are separate jobs.** The diagnosis job has no PR
  write permission, no gateway secrets, and disables checkout credential
  persistence. A trusted publication job validates the result artifact before
  commenting.
- **Fork pull requests are skipped by the `head_repository` guard.** Same-repo
  pull requests are also treated as untrusted during diagnosis; only the
  bounded result is exposed to the publication job.
- **The PR comment step is best-effort.** Without `pull-requests: write` the job
  summary and artifact still work.

## Local reproduction

```sh
causent diagnose --repo . --base origin/main
```

`causent diagnose` reads `.causent.yml` when flags are not supplied, and prints
the replay command for the bundle it writes.
