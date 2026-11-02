# Evaluation corpus schema

The authoritative schema is implemented as strict Go structs and validation in
`internal/evalcorpus`. YAML decoders reject unknown fields. This directory is
reserved for a generated JSON Schema if a non-Go corpus editor needs one.
