# Prompt TSG four-arm census freeze

## Prospective status

This document freezes the Prompt TSG study before its first intervention or code-generation
request. No generated code, Security Oracle result, Functional Oracle result, assignment outcome,
arm contrast, or effect estimate from this population was available when the population and
configuration were fixed.

The earlier 12-task Prompt TSG calibration used tasks already exposed by the 2026-08-25 study. It
was used only to repair representation defects: closed semantic guidance, typed-edge projection,
non-standard JSON contract preservation, and whitespace-exact evidence localization. Those tasks
are absent from this study.

## Population construction

The source frame contained 133 Python clusters in CWE-22, CWE-78, CWE-89, and CWE-502 after
excluding every cluster in both previous 60-task formal populations. The frozen LLM_FACTS
extractor returned 129 valid source Prompt TSGs. Four proposals were rejected because their quoted
evidence was not an original prompt span. Deterministic four-valued queries then produced:

- 55 `applicable` tasks;
- 49 `not_applicable` tasks;
- 20 `unresolved` tasks;
- 5 tasks whose actionable feature was already present.

The formal population is the complete 55-task applicable census; there is no post-TSG sampling or
replacement. It contains 28 CWE-78, 7 CWE-89, 10 CWE-22, and 10 CWE-502 tasks. Source lineages are
CyberSecEval Instruct Prime 29, CodeSecEval/SecurityEval lineage 12, SeCodePLT 9, LLMSecEval 4,
and SecurityEval 1. This lineage concentration limits generalization. It does not confound the
within-task four-arm comparison because every admitted task receives all four assigned arms.

## Frozen representation and intervention

Each source task has one Prompt TSG bound to its `task_id`, prompt hash, extractor identity, and
catalog hash. Catalog-bound source, sink, constraint, and safety semantics participate in the
finite context queries. Task-local text remains evidence-bound and cannot create a new global
feature identifier.

The LLM intervention executor receives the source task, functional contract, the selected Prompt
TSG query evidence, and the frozen MechanismSpec delta. After independent semantic validation:

- Absent keeps the source graph unchanged;
- Specific adds the selected actionable feature;
- Generic adds `control.generic_security`;
- Placebo adds `control.code_style`.

These are deterministic typed graph patches, not four new extraction calls. Prompt TSG edges are
semantic requirement relations, not causal edges. Generated code is measured independently and is
not a Prompt TSG node or causal mediator.

## Estimand and execution gate

The population has 55 task clusters and 220 assigned-arm observations. The primary estimand is the
paired, cluster-weighted assigned-arm ITT contrast `Specific - Placebo` for Oracle-evaluable secure
code yield. Functionality, code validity, Oracle support, unknown coverage, and joint
secure-and-functional success remain separate outcomes or diagnostics. Unknown is never encoded as
secure, and no post-assignment diagnostic filters the denominator.

Five tasks spanning path confinement, archive extraction, JSON deserialization, command execution,
and SQL value parameterization form the protocol-integrity pilot. Pilot assignments remain in the
final ITT. Scaling may depend only on artifact closure, valid intervention semantics, functioning
measurement, and total assignment accounting—not on effect direction, magnitude, or significance.

## Frozen identities

- source candidate task SHA-256: `a6d4a87f74774db4a8e881097ab2a72d22af4fc0402cf6bfe0d28e43570ce6ac`;
- final 55-task SHA-256: `1f551836156cdc3090d0579c1f16218616ec1c4c8df09f58b8193455c42ee6c5`;
- binding report bundle SHA-256: `b537c7e4338749081f81e54447f5fb4ae8e63e434229b69d4afa3a4e6603ac4d`;
- Prompt TSG catalog file SHA-256: `f074c672efd9c125fb6809a7b7ee0d9bf5996a5296858b4d79fd8f87f5a32237`;
- extractor config SHA-256: `12b5ccd5a1729c6cf1e96584fae823bb854d761ea6c847ceba8f5109c8305828`;
- extractor prompt SHA-256: `26e8307593800e9ec40305cba4d5a34af66ebc147fa6ba48e710e5dda8fcb963`;
- formal config SHA-256: `ceab58acf74d32233a96dd4f083c4c5f9265088136f20b1c680e917798f3b514`;
- zero-call preflight bundle SHA-256: `0375a70416bee99100e01adc55c500a52dadc7f4a3fe07700a634e560aa85e8c`.

The raw Prompt TSG extraction bundles are closed under
`/home/wsy/prompt-mechanism-study-experiments/prompt-tsg-candidates-01e55ee-20260826-08`.
They contain prompts and raw model responses and therefore remain outside the default compact
reviewer tree; the selected task file contains every source graph and binding needed by the active
experiment.
