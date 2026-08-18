# Five-CWE randomized discovery scale-up v1

## Frozen role

This stage adopts the previously approved randomized exploratory-discovery design for the frozen
five-CWE task population. Natural observational FCI remains the identifiability baseline and has
already established that the scoped security features are constant absent in the natural Prompt
distribution. Randomized discovery is separately labeled and uses only the 51 held-in discovery
tasks. The 42 confirmation tasks remain outcome-blind and inaccessible until hypothesis selection
is frozen.

The primary structural table is pooled across the five typed CWE mappings but never across model
strata. Each task has four Prompt arms, and every bootstrap draw resamples complete task clusters.
The pooled variable means that the operation-specific security requirement applicable to that
task's frozen CWE profile is present; it does not erase the typed child feature or Oracle profile.

## Frozen analysis rule

For each model, the table contains CWE scope, randomized discovery arm, realized operation-specific
requirement, generic-reminder and length-placebo Prompt features, CWE security outcome, and the
secure-and-functional joint outcome. Generated-code structure is not a causal TSG variable.
Security or functional unknowns remain assigned ITT rows and contribute zero to the corresponding
binary outcome; they are also reported as diagnostics. Post-randomization filtering is forbidden.

Raw augmented FCI and JCI-constrained FCI use causal-learn, G-square at alpha 0.05, depth 3, and
maximum path length 6. Neither analysis requires an adjacency being tested. The raw analysis places
no restriction on edges incident to the discovery context; the JCI analysis separately commits
randomized-context exogeneity and preserves both the raw and assumption-oriented PAGs.

Stability uses 200 task-cluster bootstrap draws, rejects a run if more than 10% fail, and requires
support of at least 0.8. Possible causal paths start at the pooled operation-specific Prompt feature
and end at the joint outcome or CWE-security outcome. At most three native paths per model are
frozen, ordered by stability, outcome priority, shorter path, and canonical ID. If no path passes,
the native candidate yield is zero; no edge is forced and no alternative method is selected after
seeing outcomes.

The already frozen pooled policy ITT is run on held-out tasks regardless of native discovery yield.
This preserves the intervention RQ without mislabeling a preregistered catalog contrast as a
discovered hypothesis. A result receives the discovery-confirmation label only if its path was
frozen from discovery before any confirmation outcome existed.

## Scale and call budget

The discovery population is 51 tasks: 21 CWE-78, 10 CWE-89, 7 CWE-502, 10 CWE-328, and 3 CWE-338.
Four arms produce 204 generated assignments per model and 408 across the two model strata. Gate B is
model-independent and may call the locked Prompt intervention/extraction service once per unique
source or variant; Gate C generation and the one-pass functional Judge remain model-specific. Every
phase is pilot-first and receives a new immutable output directory.

## Zero-call gate status

The corrected input bundle `five-cwe-randomized-discovery-inputs-20260818-11` contains 51 Prompt
records and 51 functional contracts. Its selection file contains the same 51 discovery task IDs and
all 42 disjoint confirmation task IDs as forbidden inputs. It records zero provider calls, zero
generated programs, and zero observed outcomes.

Qwen and Phi Gate A are frozen separately at
`five-cwe-randomized-discovery-gate-a-qwen7b-20260818-12` and
`five-cwe-randomized-discovery-gate-a-phi14b-20260818-13`. Each passed with 51 balanced blocks,
204 variants and assignments, five typed candidates, 42 excluded confirmation tasks, and no error.
Their candidate, source-Prompt, variant, and deterministic Prompt-TSG files are byte-identical; only
the model-bound assignments differ. The deterministic extractor recognized 2 of 51 intended target
features and is retained only as the registered diagnostic, so it does not authorize outcome text.

The model-independent Gate B preflight closes over every Gate A task and freezes 204 intervention
calls plus 255 blind extraction calls (51 sources and 204 variants), for a hard upper bound of 459
external calls. The application limits are 51 protocol instances, 204 arm executions, and 51 task
blocks. No call was made during this preflight.

## Incident log

- The first targeted test launch reused a repository-local pytest base path without first creating
  its parent. Five tests failed during setup before entering their bodies; no provider, experiment,
  or product path ran. The parent was created explicitly and the same bounded set passed 5/5.
- The first formal all-discovery input bundle correctly contained all 51 selected rows and 42
  forbidden rows, but its report inherited the single-task canary field shape and retained only the
  final task ID for each CWE in `selected_task_ids_by_cwe`. It made zero provider calls and is
  preserved as `five-cwe-randomized-discovery-inputs-20260818-10`. The adapter now writes a sorted
  task-ID list per CWE and records its source digest; the corrected immutable bundle is
  `five-cwe-randomized-discovery-inputs-20260818-11`.
- A cross-model Gate A digest check used the obsolete filename `prompt-tsgs.jsonl` and stopped after
  confirming the first three shared files. Listing the actual directory showed the current name is
  `deterministic-prompt-tsg.jsonl`; no artifact was changed. A subsequent test search also passed a
  Windows wildcard directly to `rg` and failed before reading tests. The corrected search uses
  `-g`, matching the repository command rule.
- A guarded cleanup of the repository-local pytest temporary directory was rejected by the host
  policy before process creation; no file was deleted. `.tmp/` is now treated as a test-cache path
  in `.gitignore`, while all formal experiment inputs, commands, environments, reports, and failed
  or superseded experiment directories remain tracked.
- The first checkpoint credential scan repeated the already documented mistake of passing Windows
  wildcard paths directly to `rg`. It ran only after 46 tests and 49 JSON validations had passed,
  then stopped before scanning or diff checks; no artifact changed. The corrected checkpoint passes
  directory roots and uses `-g` only inside `rg`. Future stage commands must use that form.
- The first corrected root-level credential scan was broader than the checkpoint and matched
  unrelated historical source, tests, and generated-code text containing test or random lookalike
  sequences. It printed paths only and changed nothing. The final gate passes a literal array of
  only this checkpoint's files and directories, without shell wildcards.
