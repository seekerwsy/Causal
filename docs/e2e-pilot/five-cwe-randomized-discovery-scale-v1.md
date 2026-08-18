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

Before that budget is released, `five-cwe-randomized-discovery-gate-b-pilot-v1` runs one held-in
CWE-78 task through the identical scale Gate B implementation. Its hard budget is four intervention
calls and five blind extraction calls. The pilot output is engineering evidence only and is excluded
from the main discovery table; the main 51-task run starts from its separately frozen inputs rather
than importing pilot outcomes.

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
- The first server Gate B pilot command inherited the target machine's base Python 3.14 rather than
  the frozen project environment and failed while importing YAML before the runner created its
  output directory. It made zero provider calls. The corrected command pins the existing Python
  3.12.12 environment, deployment `PYTHONPATH`, working directory, and output path; the nine-call
  pilot then passed without validation failures.
- The first full Gate B run preserved 51 source responses and 157 intervention plus 157 variant
  extractor responses before failing closed on the latest extractor response. That response was
  semantically complete and used unique verbatim evidence, but omitted `relation_feature_ids` only
  from eight `absent` facts whose evidence lists were empty. The strict parser formerly required
  the key even when its only valid value was an empty list. Response normalization v1 now inserts
  only that one structurally implied empty list; it still rejects the omission for `present` facts,
  any nonempty evidence, every other missing key, and every extra key. The parser version is bound
  into the extractor policy digest while the provider request bytes remain unchanged. Recovery must
  first replay every saved pair with live calls disabled, then may call the provider only for pairs
  absent from the preserved run.
- The first local verification command resolved the Windows Store Python shim and returned no test
  output; the next command used the repository environment but initially imported the main checkout
  because its editable path preceded the worktree. Setting `PYTHONPATH` explicitly to this
  worktree's `src` produced the intended bounded result. A readback also caught one test assertion
  accidentally nested under the new digest test before the successful test run; no experiment or
  provider path was entered.
- The first expanded local check assumed Ruff was installed inside the repository environment and
  referenced a removed `test_exploratory_gate_b.py` name. Ruff was instead available from the
  offline tool cache, and the active tests are split across scale, placebo, and extractor
  revalidation files. The corrected bounded run formatted the changed files, passed import/error
  checks, and passed all 86 selected tests. Ruff's unrestricted rule set also reported four existing
  broad exception boundaries in the extractor; they are intentional fail-closed translations and
  were not changed as part of this response-schema repair.
- The first zero-live-call server replay matched all 51 source extraction requests, then failed
  before parsing the first variant response because its reconstructed request bytes differed from
  the preserved request. The initial repair had included the response-normalization version in the
  extractor policy digest, but that digest also authenticates blind variant prompt and task IDs.
  Consequently, a local parsing policy accidentally changed provider request identity. The repair
  now preserves the original extractor/request digest and records a separate versioned response-
  normalization digest in the Gate B report. This keeps replay byte-exact while making the bounded
  local default independently auditable; the failed zero-call replay is preserved and made no live
  provider call.

## Gate B scale result

The corrected zero-live-call replay consumed all 365 complete historical pairs: 157 intervention
responses and 208 extractor responses. It then stopped at the first absent intervention response,
as required, without making a provider call. The resumed run reused those 365 pairs and made only
the remaining 94 calls (47 intervention and 47 extractor). It passed with 51 source extractions,
204 balanced four-arm variants, 204 blind variant extractions, 204 assignments, zero errors, and
zero pending records. All generic controls were realized and all 51 length-matched placebo checks
passed.

All 204 variant delta validations passed. The arm-blind extractor reported task-feature projection
changes for 22 variants: 13 on process launch, five on message hashing, and four on security-random
generation. These are retained as measurement diagnostics rather than filters: every submitted
variant preserved the source Prompt as an exact prefix, every registered non-task delta passed, and
the analysis table obtains task/CWE scope from the frozen dataset rather than the variant extractor.
The diagnostic therefore neither drops assigned rows nor changes ITT membership.

The pilot, both failed runs, the successful zero-call replay, and the completed run are preserved in
`data/e2e-pilot/five-cwe-randomized-discovery-gate-b-archives-20260818`. The complete archive's
internal manifest covers 1,601 files with no missing file or digest mismatch, and the archive does
not contain `.env`. The next permitted stage is a bounded real-outcome Gate C canary; Gate B itself
does not authorize a scientific claim or inspect generated-code outcomes.
