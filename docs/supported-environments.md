# Supported environments

| Environment | Detection | Automatic workflow setup | Command requirement |
| --- | --- | --- | --- |
| Go | `go.mod` | Go via `go-version-file` | Configure the exact failing command |
| Node.js | `package.json` and lockfiles | None | Configure command and package-manager setup |
| Python | `pyproject.toml` or `requirements.txt` | None | Configure command and Python setup |
| Rust | `Cargo.toml` | None | Configure command and Rust setup |
| Bazel | `MODULE.bazel`, `WORKSPACE`, or `.bazelversion` | None | Explicit command and flags required |

Manifest detection is not compatibility validation. Native libraries, service
dependencies, matrix-specific flags, credentials, and generated files must be
provided by the target repository’s CI job.
