# External validation report

## Verified in this checkout

- Clean release-style build with `go build -trimpath ./cmd/causent`.
- Version reporting from the built binary.
- Non-interactive onboarding in a temporary Go repository.
- Generated reusable-workflow reference and workflow inputs.
- Full automated test suite with model environment variables unset.
- Workflow YAML structural tests included in the repository.

## Not yet externally verified

No third-party repository was mutated, given a deliberately failing CI run, or
validated with a maintainer in this release-preparation pass. That requires
repository owners, credentials, and permission to create CI failures or pull
requests. The current repository therefore does not claim installation success,
diagnosis accuracy, maintainer acceptance, or repeat usage for external users.

## Required next validation

Run the same pinned release against one Go, one Node/Python, and one Bazel/C++
repository. Record binary version, setup changes, exact command, reproduction
result, classification, evidence bundle, maintainer-confirmed cause, elapsed
time, and setup friction. Publish results with sample sizes and separate
deterministic and live-model runs.
