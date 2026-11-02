# Evaluation corpus schema

The authoritative schema is implemented as strict Go structs and validation in
`internal/evalcorpus`. YAML decoders reject unknown fields. This directory is
reserved for a generated JSON Schema if a non-Go corpus editor needs one.

`base_run_url` is optional metadata for the separate CI run used to establish
that a `pre_existing` failure was already present on the base revision.
