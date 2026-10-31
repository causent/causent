# M7 benchmark corpus

`corpus-v1.json` is a small, versioned Python fixture corpus. Cases pin the
fixture revision labels and record provenance, expected failure signatures, and
verification commands. The corpus is intentionally a seed set for framework
validation, not a representative sample of software defects.

Add cases without changing the evaluation engine. A case must provide a stable
repository path, deterministic reproduction command, buggy/known-good revision
labels, and ground-truth root-cause metadata.
