# Discovery v2 Code-Mechanism Design

## Status and purpose

This is an exploratory method-development stage created after discovery v1 and its held-out policy
ITT were observed. It cannot retrospectively create a preregistered v1 hypothesis. Its purpose is to
determine whether a future, independently validated discovery stage should include generated-code
mechanism variables between Prompt interventions and outcomes.

Discovery v1 remains the immutable Prompt-only baseline. Confirmation outcomes may not select a v2
variable, CI test, stability threshold, candidate, or stopping rule.

## Ordered gates

1. Audit mechanism variation without running a model, Judge, analyzer, or causal backend.
2. Run the audit on one lexicographically selected task per CWE and model.
3. If the pilot is internally valid, replay the identical projection on all 51 discovery tasks.
4. Add a typed `Z` role and build Prompt+Code-mechanism tables only if both model strata contain
   mechanism variation and at least one target/no-op task transition.
5. Run the frozen causal-learn FCI/G-square analysis first. Other established backends or CI tests
   are labeled sensitivity analyses and cannot rescue a failed primary path.
6. Freeze the v2 method before any newly acquired validation-task outcome is generated.

## Mechanism projection

The source is the arm-blind `mechanism_trace` inside authenticated `oracle-analysis.json`, before
`oracle-decision.json` is read. The projection uses only the target CWE and the finite sink facts:

- `unavailable`: no generated code or a syntax-invalid trace;
- `no_relevant_sink`: no sink fact for the target CWE;
- `proved_safe`: at least one relevant sink and every relevant sink is `safe`;
- `proved_unsafe`: at least one relevant sink is `unsafe`;
- `unresolved`: no unsafe sink exists and at least one relevant sink is `unresolved`.

`z_target_mechanism_realized` is one only for `proved_safe`; all assigned rows remain present and
all other states map to zero. The categorical state remains a diagnostic. The projection never
uses the persisted security label or functional-Judge result.

Each row binds the archive, unit manifest, Oracle analysis, trace, assignment, task, model, CWE, and
arm. Each task must form one complete four-arm block in both model strata.

The historical discovery archives have no run-level manifest. Their immutable archive SHA-256 and
all 204 unit manifests are therefore authenticated separately; the audit records this historical
boundary instead of synthesizing a missing top-level manifest.

## Causal table planned after the audit

The primary v2 development view is the randomized target/no-op subset:

`W(CWE) -> X(operation-specific requirement) -> Z(mechanism realized) -> Y`

`Y` is analyzed in separate tables for CWE security and secure-and-functional success. A full
four-arm JCI table and the exact Prompt-only v1 table are sensitivity/baseline views. Temporal and
typed background knowledge forbids backward directions but requires neither `X-Z` nor `Z-Y`.

The primary candidate must start at the operation-specific Prompt feature, include the registered
mechanism variable, end at the single registered outcome, exclude JCI context from the path, and
meet the unchanged 0.8 task-cluster bootstrap stability threshold. A zero-path result remains valid.

## Validation and stopping rule

Old discovery outcomes may be used only for v2 method development. A publishable v2 discovery
claim requires a new outcome-blind task allocation and a frozen analysis manifest before generation.
The ordered search stops when either:

- a stable path replicates under the frozen method on independent validation tasks; or
- the preregistered data/method ladder is exhausted and produces a reproducible identifiability or
  mechanism-variation boundary.

Changing methods until a positive edge appears is forbidden.

## Execution incidents

- The first pilot stopped before output creation because the reused held-out archive verifier
  required a run-level manifest that the historical discovery archives never contained. The
  corrected audit retains archive-level SHA-256 binding and verifies every unit manifest. No model,
  Judge, analyzer, or causal-backend call occurred.
- The first typed-Z test command named two obsolete test paths, so pytest collected no test and no
  product code ran. Listing the repository tests first located the active background and path suites.
- The first causal-schema extension raised the variable tier ceiling to three but retained a second
  hidden tier ceiling in the background-knowledge contract. The new unit test failed before any
  experiment run. Updating that same contract to accept tier three allowed all 103 targeted schema,
  background, JCI, and path tests to pass; existing tier-zero-through-two records remain valid.
- The first v2 reference-FCI invocation reached no backend call and created no output because the
  execution entry point used a nonexistent `CausalTableRecord.variable_ids` convenience property.
  Helper-level tests had not exercised that branch. The entry point now derives IDs from the typed
  variable records; the same frozen Qwen primary invocation is rerun after targeted regression.
- The corrected entry point then reached the backend, which rejected the 102-row target/no-op table
  because it was labelled observational even though each of 51 tasks contributed a randomized
  two-row block. No output directory was created. The replacement v2 table explicitly includes the
  JCI arm context and uses JCI raw/constrained run kinds; it does not bypass the one-row-per-task
  observational safeguard. The one-off diagnostic command record initially named the diagnostic
  script incorrectly; a separate corrected command record is retained without deleting the first.
- Before the first v2 bootstrap, its global seed was briefly added to the already-used reference
  analysis config. Provenance verification detected the resulting digest drift before any bootstrap
  run. The analysis file was restored byte-for-byte (its SHA-256 again matches the reference PAG),
  and a separate frozen bootstrap config now owns the seed and resampling contract.

## Mechanism audit result

The corrected five-task pilot completed 40/40 rows. The full replay completed 408/408 rows from 51
tasks, two model strata, and four arms, with zero provider call, zero outcome payload consumed, zero
error, and zero pending row.

Qwen's target arm realized the target code mechanism in 31/51 tasks versus 21/51 under no-op. Ten
task pairs improved and none were harmed. Phi realized it in 29/51 target tasks versus 26/51 no-op
tasks; six pairs improved and three were harmed. All five mechanism states occurred in the full
population except that Qwen had no unavailable row. Both model strata therefore pass the frozen
variation gate.

This is a measurement-availability result, not a causal-discovery claim. It authorizes the typed Z
table implementation without changing the FCI, bootstrap, or independent-validation requirements.

The subsequent provenance join completed first on five tasks and then on all 51 tasks. The pilot
contains 40 joined rows and the full bundle contains 408, with eight model/view matrices in each
bundle and zero provider call or dropped assignment. For each model, target/no-op security and joint
views contain two rows per task and the full JCI views contain all four. Z is read only from the
mechanism audit, while Y is read only from the previously archived discovery-v1 result assembly;
their assignment, task, model, arm, and CWE coordinates must match exactly.

The explicit-context table replay completed 40/40 pilot and 408/408 full joined rows with zero
error. All eight model-by-view reference FCI runs then completed. Every raw and JCI-constrained PAG
contains a `Z -> Y` edge and the context tables contain the deterministic arm-to-feature relation,
but none contains an `X-Z` adjacency; therefore no exact possible `X-Z-Y` path exists at the
reference stage. Because `c.arm` and the arm-specific feature indicators are deterministic copies,
the next method-development step tests the standard nonredundant JCI representation (`C-Z-Y`)
under a new frozen analysis record. It may not be reported as independent confirmation.

The nonredundant JCI replay excluded the arm-deterministic operation-specific indicator while
retaining its semantics in the frozen target and protocol identifiers. Seven of eight reference
views still had no complete context-mechanism-outcome path. Qwen's target/no-op joint-outcome view
alone produced `C o-o Z -> Y`; JCI exogeneity oriented the first edge as `C -> Z`. A ten-replicate
engineering bootstrap completed without backend failure and supported the path three times. The
frozen 200-replicate task-block bootstrap then completed 200/200 with zero failure and support
81/200 (0.405), below the unchanged 0.8 threshold. No hypothesis was frozen. This distinguishes a
reference-sample candidate from a stable discovery and motivates more independent tasks rather
than threshold relaxation.

## Semantic provenance audit and functional-outcome extension

File-level provenance separation was necessary but not sufficient. A row-level semantic audit
found that `z.target_mechanism_realized` was identical to the CWE-security outcome in all 408
discovery rows and all 336 historical held-out rows. The joint outcome was the conjunction of the
same security decision and functional success. Consequently, the previously observed `Z -> Y`
edges for security and joint outcomes are definitional relationships, not evidence that a code
mechanism mediates a security effect. These outcomes are excluded from subsequent discovery with
this Z variable. This audit is retained as a methodological finding: mechanism and outcome
variables must be separated by semantic derivation, not merely by artifact file.

A new method-development table therefore uses only the independently derived single-pass
functional-Judge outcome, `y.discovery_functional`. It combines the 51 original discovery tasks
with 42 complete historical held-out tasks, for 93 complete four-arm task blocks per model and 744
rows overall. These historical held-out outcomes are reused only for method development; any
scientific claim still requires a newly allocated independent validation set after the method is
frozen.

Four reference FCI/JCI analyses completed without backend failure. Qwen's target/no-op view had a
context-to-mechanism adjacency but no mechanism-to-function adjacency, while its four-arm view had
neither. Phi's target/no-op and four-arm views had a directed mechanism-to-function edge but no
context-to-mechanism adjacency. Thus no model/view contained a complete
`context -> mechanism -> functional outcome` chain. The result separates two partial phenomena:
the target patch shifts Qwen's security mechanism without detectable functional coupling, whereas
Phi exhibits mechanism/function coupling without a detectable target-patch shift.

The direct Phi four-arm mechanism/function edge was frozen as a sensitivity target with the same
0.8 task-block stability threshold. A ten-replicate engineering pilot completed 10/10 runs without
failure and supported the edge in 6/10 replicates. Inspection confirmed that the other four PAGs
truly omitted the edge; the 0.6 result is not caused by endpoint-matching policy. The frozen
200-replicate run, rather than any relaxed edge definition, determines whether this partial
association is stable.

The frozen full run completed 200/200 task-block replicates with zero backend failure. The directed
`z.target_mechanism_realized -> y.discovery_functional` edge appeared in 167/200 replicates
(0.835), above the preregistered 0.8 threshold, and produced one frozen hypothesis. This is the
first stable, semantically non-definitional discovery in the method-development ladder. Its scope
is deliberately narrow: it identifies Phi's four-arm mechanism/function coupling, not target-patch
mediation, because the same reference PAG contains no context-to-mechanism adjacency. Qwen provides
the complementary model boundary: its target/no-op context changes mechanism realization, but no
mechanism/function edge appears. The hypothesis remains ineligible for a scientific claim until it
is evaluated on a newly allocated independent task set under the frozen protocol.
