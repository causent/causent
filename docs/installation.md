# Installation and troubleshooting

## Install a released binary

Malenia releases currently publish a Linux amd64 binary named
`malenia_linux_amd64`. Download it from the GitHub release, make it executable,
and place it on `PATH`:

```sh
curl -fL https://github.com/causent/malenia/releases/latest/download/malenia_linux_amd64 -o "$HOME/.local/bin/malenia"
chmod +x "$HOME/.local/bin/malenia"
malenia version
```

The binary is built for Linux amd64. `v0.3.0` is an example release tag for a
fixed binary version. `v1` is the major-version tag used for the reusable
workflow; it is not the name of a different installer.

## Onboard a repository

Run `malenia init` as documented in [CI integration](ci-integration.md). Review
an empty `command` before committing: Malenia will not infer a test command from
a manifest alone.

## Troubleshooting

- `command is required`: add the exact failing CI command to `.malenia.yml`.
- `command never executed`: verify the runtime/toolchain is installed on the
  runner or select a Docker image.
- `Docker image is required`: use `executor: docker` with `image: ...`.
- No PR comment: check `pull-requests: write` permission and that the run is
  not from a fork.
- No release download: confirm that the repository has a published release and
  that the workflow’s `malenia_version` matches its tag.

The reusable workflow is Linux amd64-oriented and the current integration is
GitHub Actions-specific. Node, Python, Rust, and Bazel projects must provide a
runner setup that installs their toolchain; only Go is automatically configured
by the reusable workflow today.
