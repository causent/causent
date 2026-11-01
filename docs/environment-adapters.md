# Environment adapters

Causent keeps repository-specific environment knowledge outside the diagnosis
engine in `internal/environment`. An adapter detects evidence, reports runtime
metadata, provides dependency-preparation commands, and may provide a
conservative test command. The configured command always wins; CI-discovered
commands should be supplied as evidence before adapter defaults.

Supported adapters currently cover Go (`go mod download`), Node.js (npm,
pnpm, and Yarn lockfiles), Python (pip, Poetry, and Pipenv manifests), Rust
(`cargo fetch`), and Bazel. Bazel intentionally does not invent a test target:
repositories must configure the Bazel command and flags explicitly.

Preparation commands are ordinary structured commands and must be run through
the existing policy-bounded local or Docker executor. Adapters do not own
diagnosis, classification, worktree management, secrets, or resource limits.
Missing runtimes, native libraries, and ambiguous CI matrices remain execution
observations rather than compatibility claims.
