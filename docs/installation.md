# Installation and troubleshooting

## Install a released binary

Causent releases currently publish a Linux amd64 binary named
`causent_linux_amd64`. Download it from the GitHub release, make it executable,
and place it on `PATH`:

```sh
curl -fL https://github.com/causent/causent/releases/latest/download/causent_linux_amd64 -o "$HOME/.local/bin/causent"
chmod +x "$HOME/.local/bin/causent"
causent version
```

The binary is built for Linux amd64 and requires the runtime libraries needed
by its SQLite build. Other platforms should build from source until release
artifacts are published for them.

## Onboard a repository

Run `causent init` as documented in [CI integration](ci-integration.md). The
released executable is still named `causent` for compatibility, so the same
command is currently invoked as `causent init`. Review an empty `command` before
committing: Causent will not infer a test command from a manifest alone.

## Troubleshooting

- `command is required`: add the exact failing CI command to `.causent.yml`.
- `command never executed`: verify the runtime/toolchain is installed on the
  runner or select a Docker image.
- `Docker image is required`: use `executor: docker` with `image: ...`.
- No PR comment: check `pull-requests: write` permission and that the run is
  not from a fork.
- No release download: confirm that the repository has a published release and
  that the workflow’s `causent_version` matches its tag.

The reusable workflow is Linux amd64-oriented and the current integration is
GitHub Actions-specific. Node, Python, Rust, and Bazel projects must provide a
runner setup that installs their toolchain; only Go is automatically configured
by the reusable workflow today.
