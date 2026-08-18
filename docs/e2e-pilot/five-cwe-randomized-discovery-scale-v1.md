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

## Gate C frozen plans

Gate C retains the original bounded-canary path and adds one explicit full-population path. The
former accepts two through five named tasks; the latter accepts only the exact 51-task Gate B
population and therefore exactly 204 four-arm assignments. Qwen2.5-Coder-7B and Phi-4-14B plans
inherit their own Gate A assignments and seeds, while their 204 Prompt variant IDs and task set are
identical. Their generated-code assignments are model-specific and disjoint.

The two five-CWE structural pilot plans each contain five tasks and 20 balanced assignments. The two
main plans each contain 51 tasks, 204 generation requests, 51 frozen functional contracts, and 51
profile-scoped Oracle coverage records; none has unknown coverage. Every plan is closed by an
11-file manifest, and the pilot assignment IDs are proper subsets of their corresponding main
plans. The live preflight validated all 204 assignments in each model stratum with zero generation,
Judge, or Oracle calls.

The earlier two-model main-Prompt canary already exercised real generation, one-pass functional
judgment, and Oracle v2 for all five CWE families. To avoid creating deterministic duplicate outputs,
the new balanced five-CWE plans serve as zero-call mapping checks. Each 51-task main run next executes
one selected target-patch assignment as an in-population pilot; only a complete pilot authorizes its
remaining 203 assignments. Qwen and Phi services run sequentially on the same GPU.

Additional execution incidents were non-experimental. A source search again passed a Windows
wildcard directly to `rg` while locating service paths and failed without reading or changing a
file; the corrected search uses explicit directories. The first expanded Gate C test edit inserted
five pre-existing scale-canary assertions below the new parametrized test, so 2 of 90 tests compared
the 204-unit configuration with the old eight-unit expectation. Later zero-call preflight commands
still ran because PowerShell returned the final command status. The assertions were restored to
their original test, subsequent native commands now check `$LASTEXITCODE` immediately, and the same
90-test set passed. Both preflights made zero provider calls.
- The first final Gate C credential scan repeated the Windows wildcard error for the newly added
  config basename and exited after the 90 tests had passed. It did not read secrets or mutate an
  artifact. The corrected scan passes the config directory literally and applies the basename with
  `rg -g`; literal source, script, test, and document paths are scanned separately.
- The first Qwen main-population Gate C pilot inherited the earlier Gate B CPython 3.12.12
  environment. Its generation and functional-Judge calls completed, but the Oracle runtime gate
  rejected the process before either analyzer call. The failed directory is preserved with a
  zero-call Oracle session; recovery reused both provider responses and ran the Oracle under the
  already calibrated CPython 3.12.13 runtime and compatibility-tool directory. A later readback
  mistyped the repair-report basename and changed nothing; listing the output directory located the
  authenticated report.
- The first Qwen remaining-phase run completed 51 assignments and failed closed on assignment
  `assignment_3108799fd624e7403e6521a082a3bb31657ac35cd00d7996822d1ad456e59c67`.
  Bandit 1.9.4 B608 had emitted the parent f-string line range 9--17 together with a child AST
  Constant endpoint at line 16, column 39. The adapter had placed that child column on parent line
  17, where it was out of bounds. The bounded repair changes no rule or label: already valid
  coordinates remain byte-identical; an invalid Bandit endpoint is recovered only when CPython
  3.12 AST yields one unique endpoint matching the reported start line, start column, end column,
  and enclosing line range. Missing or ambiguous matches still fail closed. While diagnosing the
  preserved unit, one manual path copied from wrapped terminal output omitted one hexadecimal
  character and one neighboring-regression command named two nonexistent test files; both commands
  stopped before product execution or artifact mutation. The corrected path was discovered from
  the error-status relation, and the corrected targeted test set is selected from `rg --files`.
- The recovered Qwen run then completed all 204 assignments with zero error and zero pending unit.
  Its aggregate result contains 103 secure, 47 insecure, and 54 Oracle-unknown decisions; 143
  functional passes, 51 functional failures, and 10 functional unknowns; and 81
  secure-and-functional outcomes. The final run assignment set is byte-for-byte identical to the
  204-ID frozen plan set. The complete archive has SHA-256
  `561b797639c7669bb3745a2e73b79543733635caaf86c1cac3ff3759439cced1`; a local replay
  revalidated all 204 unit manifests. The first local extraction used a worktree path whose run and
  assignment components exceeded the Windows legacy path limit, so enumeration returned no unit
  rows and a recursive inspection produced path errors. The archive was not modified; extracting
  the same bytes under `D:\MyCode\Causal\.tmp\q1` yielded 204 complete and zero failed units.
- Two preparatory source inspections guessed obsolete filenames (`variants.jsonl` and
  `discovery/_fci_worker.py`) instead of listing the active files first. Both were read-only and
  changed no artifact. The corrected reads use `prompt-variants.jsonl` and the actual supervised
  FCI module locations; future analysis preparation starts from `rg --files`.
- The first Phi remaining-phase execution completed 41 assignments and preserved one generation
  error before stopping. The local service returned a well-formed response with
  `finish_reason=length`, exactly 1,024 completion tokens, and a truncated response containing a
  deterministic repeated branch. This is neither an API outage nor an Oracle failure. Provider-
  result policy v2 classifies `length` as `token_limit` terminal-no-code only when completion usage
  exactly equals the one frozen request limit. The partial text remains transport evidence and is
  never imported as code; the assigned row remains in ITT with joint outcome zero. The stopped run
  is historical and will not be merged with a policy-v2 Phi run.
- During that diagnosis, a manually copied wrapped assignment path omitted one hexadecimal
  character; the read-only lookup failed, and the exact directory was then derived from the error
  status file. Two later read-only searches guessed a nonexistent `provider_protocol.py` path and
  supplied one malformed regular expression. Neither changed a source or experiment artifact; the
  corrected inspection first enumerated the actual schema and adapter files.
- The first local verification assumed a worktree-local virtual environment that does not exist.
  A second command used the main checkout's editable environment without a worktree `PYTHONPATH`
  and also assumed Ruff was installed there. The corrected command pins this worktree's `src`, uses
  the repository Python only for pytest, and obtains Ruff from the existing tool cache. The bounded
  regression passed 431 tests; formatting and fatal import/error checks passed. Ruff's unrestricted
  current rule set reports existing broad-exception and import-order findings outside this patch,
  so it is recorded as a diagnostic rather than misreported as a clean project-wide lint gate.
- The first policy-v2 deployment transfer reused the default PowerShell launcher, which the host
  denied before starting `scp`. The explicit Windows OpenSSH command under `cmd.exe` reached the
  target but first found that the named transfer directory did not yet exist. After creating that
  mode-0700 directory, the same 9,392-KiB archive transferred and matched SHA-256
  `ac2e2d0de39096dc50730e659c2c4137215c10e25aba1d60ffbd02d424f58861`. The first import probe
  still inherited the prior deployment's `PYTHONPATH`; it exposed the old source path and did not
  run an experiment. Pinning the new deployment path then loaded commit `55c4552` as intended.
- A read-only local Qwen sample inspection passed a wildcard to PowerShell's `-LiteralPath`, so no
  unit was selected and the subsequent null-path reads failed. Enumerating the archive root first
  located the short-path `units` directory. The completed 204-row assembly then authenticated every
  unit manifest and reproduced the archived aggregate counts without dropping a row.
- A later test search again passed Windows wildcard path arguments directly to `rg`; it failed
  before reading tests. The corrected query passes the `tests` directory and uses three `-g`
  filters. The pooled-table schema check then passed all 58 causal-schema tests.
- The first policy-v2 Phi progress probe looked for the obsolete name
  `unit-closed-manifest.json` and therefore reported zero complete units even though 131 unit
  `status.json` files were already closed. It did not affect execution. Progress monitoring now
  counts exact `COMPLETE` and `ERROR` status values and reports independently created unit
  directories only as the currently running diagnostic.
- The first pooled reference-FCI attempt added the presentation role to the schema but had not yet
  registered its finite causal declaration, so the background translator failed closed before
  invoking causal-learn. The pooled W/X/P/Y declarations now live in a separate reviewed catalog;
  the existing Prompt-table catalog remains unchanged, and every pooled variable binds its exact
  declaration digest. A second reference attempt reached causal-learn but rejected the pinned
  library's unconditional visible-edge echo from `get_color_edges`. The adapter now accepts only
  the exact ordered text of returned directed edges carrying the library's `nl` property; missing,
  mismatched, or additional output remains invalid. The next immutable Qwen reference run completed
  with 204 rows and both raw and JCI-constrained PAGs.
- Two local formatting probes repeated known environment assumptions: the Windows Store `python`
  shim produced no useful interpreter output, and the repository Python did not contain Black.
  The corrected commands explicitly bind CPython 3.12.13 and the worktree `PYTHONPATH`; no source
  or experiment artifact was produced by either failed probe. A later read-only line-length helper
  also used an ambiguous PowerShell variable followed by a colon and failed at parse time; its
  corrected form uses the format operator.
- The first Phi archive transfer repeated the known interactive PowerShell-launcher failure and was
  rejected before `scp` started. The destination was then created non-interactively and the exact
  OpenSSH command ran under `cmd.exe`; both downloaded archives matched their server SHA-256.
- The first Phi result assembly authenticated all unit inputs but failed before creating its output
  directory because the aggregate run report counts Oracle `unknown` only among generated programs,
  whereas the ITT table correctly maps all three terminal-no-code rows to unknown security and then
  to outcome zero. The assembly invariant now compares its ITT unknown total with the sum of the
  report's Oracle-unknown and terminal-no-code counts. No row is filtered, and the report's original
  counting semantics are preserved rather than rewritten.
- The first three-replicate bootstrap pilot completed all FCI runs, but a subsequent top-level
  closure replay exposed that the shared manifest verifier excluded every nested file named
  `artifact-manifest.json` rather than only the root manifest being verified. Each nested manifest
  was present and correctly hashed in the top-level manifest; only the replay set was wrong. The
  verifier now excludes the exact root manifest path and continues to authenticate nested replicate
  manifests as ordinary covered files.
- The first bootstrap formatting/static probe found one unused `Any` import and stopped before any
  test or experiment run. Removing that import allowed the bounded static check and 31 targeted
  tests to pass. Two independent three-replicate Qwen pilots then produced byte-identical draw,
  matrix-commitment, PAG, support, and report artifacts. Every draw sampled 51 task clusters with
  replacement and retained all four arms, yielding exactly 204 rows per replicate; all six real FCI
  runs succeeded.

## Randomized discovery result

Both fixed model strata completed the full 200-replicate task-block bootstrap with zero backend
failure. Every replicate sampled 51 tasks with replacement and imported all four assigned arms for
each sampled task occurrence, so every FCI matrix contained 204 rows. Qwen and Phi were estimated
separately and no row was filtered after assignment.

The Qwen raw/JCI PAG pair contains five edges; the Phi pair contains six. In both strata, the three
JCI-only changes are the assumption-based orientations from randomized arm context to the three arm
feature indicators. Neither raw reference PAG contains a possible path from
`x.operation_specific_security_requirement` to either registered outcome when paths through
`c.arm` are excluded. Consequently, the frozen top-k set is empty for both models and each stratum
emits an authenticated `no_stable_hypothesis` record. This is a valid zero-yield discovery result,
not a bootstrap or G-square execution failure. Under the pre-outcome confirmation boundary, it
cannot be rescued using confirmation outcomes; the separately preregistered held-out policy ITT
must still run.

## Held-out policy-ITT Prompt freeze

The held-out input adapter selected all 42 frozen confirmation tasks and marked all 51 discovery
tasks as forbidden. Gate A created 42 randomized four-arm blocks for each model stratum, with 168
assignments per model and no provider or outcome call. The model-independent Gate B pilot then ran
one task per CWE and passed all 45 intervention/extraction calls before scale-up.

The first full Gate B run stopped after preserving 299 nominal completed or reused calls because a
95-character target suffix had no reviewed neutral placebo inside its allowed 85--105 character
interval. This was a genuine pre-generation gate failure rather than an API failure. A single
97-character presentation-only suffix was added, the failed run remained immutable, and the next
run reused 256 exact request/response pairs while making 122 live calls. The completed run passed
all 42 tasks and 168 variants: every target arm exposed the intended target feature, every control
arm withheld it, every generic reminder and length control passed, and every variant retained the
source Prompt as an exact prefix.

The blind extractor reported task-feature projection drift in 21 variants across 14 tasks. The
drift is retained as a diagnostic because exact-prefix preservation proves that no source task text
was edited, and the Gate B semantic validation independently excludes task features from the
allowed causal delta. It is not used to filter the randomized ITT population.

Additional execution notes:

- One read-only `rg` inspection passed PowerShell wildcard path arguments directly and failed
  before reading any artifact. The corrected inspection used structured JSON parsing and changed
  no run output.
- The first unrestricted Ruff probe reported two pre-existing broad-`BaseException` diagnostics
  in the fail-fast/recovery executor. Targeted Gate C tests still passed; later static validation
  remains limited to formatting and fatal import/syntax rules unless those existing handlers are
  intentionally redesigned.
- The held-out Qwen run completed 24 assignments before one parse-invalid generated program caused
  Semgrep 1.168.0 to emit a `PartialParsing` warning. The strict adapter correctly rejected that
  report, but the Oracle should not have submitted syntax-invalid code to either analyzer after the
  local syntax gate had already classified it. The corrected Oracle now excludes parse failures
  from analyzer batches, emits provenance-bound `unknown_parse_failure`, preserves the assigned row
  with joint outcome zero, and keeps valid members of a mixed batch analyzable. Recovery recognizes
  this exact closed failure state, reuses the preserved generation and functional outcome, makes no
  generation or Judge call, and records a zero-call analyzer recovery session. The original failed
  run remains immutable.
- After the parse-failure recovery, Qwen completed another 106 assignments before a `stop` response
  containing one complete fenced Python implementation followed by prose and a fenced command-line
  example was rejected. This exposed a contradiction in the existing envelope-v2 implementation:
  it named and accepted `python_fence_trailing_text`, but counted every trailing closing fence as a
  second Python implementation. The decoder now closes on the first complete Python fence, ignores
  trailing prose and non-Python fenced commands, and still rejects a second `python` or `py` fence.
  The preserved response can therefore be deterministically replayed without another generation
  call. The failed run remains immutable and the recovery records the one required functional-Judge
  call separately.
