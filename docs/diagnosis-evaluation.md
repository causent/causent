# Diagnosis contract and evaluation

The diagnosis pipeline is deterministic through reproduction, bounded output
capture, classification, evidence construction, and optional base/head
comparison and localization. The optional model receives only structured
evidence and may propose hypotheses; it cannot create evidence or alter the
classification.

Reports distinguish observed facts (`evidence` and reproduction results) from
inferences (`claims` and agent hypotheses). Every claim must reference an
evidence ID present in the same report. Confidence is a bounded expression of
support, not a probability of correctness. `uncertainty` records missing or
ambiguous information, and refused reports do not retain claims.

## Evaluation protocol

Evaluation suites are pinned JSON fixtures validated by
`internal/evaluation.ValidateSuite`. Each case must include a repository path,
buggy and known-good revisions, reproduction command, root-cause label, and
ground-truth root cause. The same pinned cases and budget must be used for:

1. deterministic diagnosis;
2. LLM-assisted diagnosis; and
3. evidence-guided LLM diagnosis.

Reports should include sample size and separately report classification
accuracy, root-cause accuracy, evidence-reference validity, reproduction rate,
unsupported claims, elapsed time, and model cost. Results from live providers
must not be combined with deterministic results, and no accuracy claim should
be made from a tiny or synthetic-only suite.

The checked-in benchmark corpus is not presented as a real-CI ground-truth
dataset. Production evaluation requires adding pinned real repositories and
reviewed labels before publishing a comparison report.

Repair remains opt-in and experimental: a patch is successful only after
isolated application, tests, and verification all pass.
