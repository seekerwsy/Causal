# FCI discovery migration (M4B)

M4B is a breaking replacement for the heuristic TSG-QCD discovery artifacts. It implements
Prompt-only, TSG-constrained observational discovery with the established FCI algorithm; it does
not introduce a general-purpose causal-discovery algorithm.

## Runtime and statistical contract

The required backend is exactly `causal-learn==0.1.4.7`, called with FCI and the G-square
conditional-independence test (`gsq`). It is the minimum runnable backend and requires neither Java,
JPype, `py-tetrad`, nor RFCI. An optional RFCI sensitivity backend remains outside M4B and cannot
alter the primary FCI result.

Each table is local to one CWE/security scope and one model. `model_id` is table provenance, not a
minimum causal variable. Variables come from the closed Prompt-side catalog:

- tier 0: pre-treatment task metadata (`W`);
- tier 1: Prompt TSG feature and motif variables (`X`);
- tier 2: independently evaluated Oracle outcomes (`Y`).

The Prompt TSG graph is structural feature evidence, not a causal graph. Generated code participates
only in Prompt-to-generation-to-Oracle provenance metadata needed to authenticate an outcome. Code
text, code structure, analyzer finding text, guards, sanitizers, and mechanisms do not enter the
causal table. There is no Code TSG and no code-side causal variable.

Background knowledge is derived before FCI. It contains temporal tiers, all forbidden later-to-
earlier directions, and the finite reviewed typed adjacency restrictions. Each adjacency exclusion
is a two-way adjacency exclusion, not a preferred orientation. Translation to causal-learn and
post-run validation enforce the same contract. `required_directions` is empty: neither an `X-Z`
edge, a `Z-Y` edge, a candidate feature edge, nor any selected path edge is required.

FCI returns a PAG. Tail, arrow, and circle endpoint marks are serialized exactly. A circle records
identification uncertainty and must not be silently oriented into a DAG. Possible-path extraction
allows only endpoint-compatible Prompt-side `X-(W|X)*-Y` paths within the configured hop and count
bounds.

## Task-cluster bootstrap and freeze

The reference draw chooses one seed for each task. Every bootstrap replicate samples task IDs with
replacement and then chooses one seed for each sampled task occurrence. All choices use the
versioned SHA-256 rejection/Fisher-Yates generator and are persisted before backend execution. This
is task-cluster bootstrap, not row bootstrap.

The configured replicate count is the support denominator. A failed replicate is recorded as a
typed failure, contributes zero support, and is never removed from the denominator. Path support
matches the exact variable sequence while treating equal endpoint marks as compatible and allowing
circle uncertainty on either side. Every path meeting the preregistered stability threshold is
frozen; confirmation outcomes cannot add, remove, rank, or rewrite it.

Freeze is performed before M5/M6 artifacts. The freeze guard rejects any existing randomized
variant, assignment, confirmation, effect, JCI, RFCI, analysis, or report artifact. Frozen IDs and
semantic digests bind the table, catalog, extraction policy, FCI configuration, background
knowledge, reference PAG, exact path, support numerator, and the failed-replicate-aware denominator.

## The 11 discovery artifacts

The causal-table transaction commits these three artifacts atomically:

1. `discovery/causal_tables.jsonl`
2. `discovery/causal_observations.jsonl`
3. `discovery/causal_exclusions.jsonl`

The FCI discovery transaction then commits these eight artifacts atomically:

4. `discovery/background_knowledge.jsonl`
5. `discovery/reference_pags.jsonl`
6. `discovery/bootstrap_draws.jsonl`
7. `discovery/bootstrap_pags.jsonl`
8. `discovery/bootstrap_failures.jsonl`
9. `discovery/path_support.jsonl`
10. `discovery/hypotheses_frozen.jsonl`
11. `discovery/discovery_failures.jsonl`

Every artifact has content-addressed IDs or digests and is covered by its committed stage manifest.
Readback revalidates exact table/artifact closure and producer provenance after transaction install.

`NO_STABLE_HYPOTHESIS` and `TOO_MANY_FAILED_BOOTSTRAPS` are terminal M4B outcomes. Their valid PAG,
draw, path, and failure artifacts are committed before the CLI maps the terminal status to a nonzero
exit. No M5 stage is started. At the M4B boundary, `secaware run-all` ends at this point and prints
`SecAware discovery complete` only for a ready discovery result.

## Migrating an existing run

Do not mix old and new discovery files. Create a fresh run directory, or remove the complete old
run and regenerate it from immutable source inputs. In particular, the old
`discovery/hypotheses_all.jsonl` and `discovery/hypotheses_selected.jsonl` are replaced by
`discovery/hypotheses_frozen.jsonl`; old score/ranking artifacts and their manifests have no M4B
compatibility path.

Run the new boundary with:

```bash
secaware discover --config configs/paper_v0.yaml --run-dir runs/paper-m4b
# Or execute all implemented stages through M4B:
secaware run-all --config configs/paper_v0.yaml --run-dir runs/paper-m4b
```

The observed generation and Oracle stages still require their documented providers, analyzers, and
runtime isolation. Their generated code is evidence consumed by the independent Oracle and is
retained only for Prompt-to-Oracle provenance; it is not reinterpreted as a Code TSG or causal
mechanism.
