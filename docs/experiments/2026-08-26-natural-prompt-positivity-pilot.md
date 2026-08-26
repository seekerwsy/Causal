# Natural-Prompt Positivity Pilot (2026-08-26)

## Status

This is a newly run, outcome-blind development pilot. It tests whether allowing
natural, unmanipulated Prompts repairs the support precondition for family-local
FCI. It does not estimate an intervention effect and has
`scientific_claim_allowed=false`.

The implementation is commit `5bde721`. The pre-edit paper checkpoint is commit
`cea4926`.

## Protocol

- Independent unit: deduplicated task unit (the frozen files retain legacy
  `semantic_cluster_*` identifiers).
- Source population: the 2,165-unit conservative seven-source curation bundle.
- Pilot scopes: the complete Python representative census for CWE-328/message
  hashing and CWE-611/XML parsing.
- Selection: 38 task units, comprising 25 CWE-328 and 13 CWE-611 units. No arm,
  generated code, Oracle outcome, or historical task effect was read.
- Representation: evidence-bound `LLM_FACTS_V1` Prompt TSG extraction with
  `qwen3.5-flash-2026-02-23`, temperature 0, one attempt per task.
- Formal positivity gate: at least 30 `PRESENT` and 30 `ABSENT` task units plus
  at least two source lineages containing both states, within the frozen context
  query.
- Development sensitivity: at least three units per state and one shared
  lineage. This sensitivity cannot promote the formal gate.

The remote extraction ran under Python 3.13.12 because the existing A800 host
did not expose the project's supported Python 3.12 interpreter. This is an
environment limitation of the development pilot, not a change to the supported
reviewer runtime.

## Experiment evidence

### E-POS-001: natural-Prompt population freeze

- Evidence type: `newly_run`.
- Status: verified.
- Command: `prompt-mechanism-study discovery-population` with frozen scopes
  `CWE-328=message_hashing` and `CWE-611=xml_parsing`.
- Inputs: `.codex-runtime/dataset-prep-seven-full-20260822-01` and
  `.codex-runtime/semantic-clusters-seven-v11-conservative-20260823-29`.
- Output: `.codex-runtime/discovery-natural-census-cwe328-cwe611-v1-20260826-01`.
- Result: 38 task units; 24 CyberSecEval Instruct Prime, 2 SALLM, 6 SeCodePLT,
  and 6 SecurityEval representatives.
- Claim readiness: `paper_ready` only as a description of this development
  population; not an effect result.

### E-POS-002: blind Prompt TSG extraction

- Evidence type: `newly_run`.
- Status: verified by both bundle manifests.
- Remote deployment:
  `/home/wsy/prompt-mechanism-study-deployments/discovery-positivity-5bde721-20260826-21`.
- Remote experiment:
  `/home/wsy/prompt-mechanism-study-experiments/discovery-positivity-5bde721-20260826-21`.
- Local immutable copies:
  `.codex-runtime/discovery-positivity-5bde721-20260826-21/tsg-{pilot,remaining}`.
- Result: 38/38 valid graph records, zero retries and zero arm/outcome inputs;
  10 graphs retained at least one unresolved context semantic.
- Claim readiness: `weaken_claim`; this validates execution and supplies pilot
  feature states but is not a population-level extractor qualification.

### E-POS-003: formal support audit

- Evidence type: `newly_run`.
- Status: verified.
- Output: `data/method/results/discovery-positivity-cwe328-cwe611-v1`.
- Aggregation level: one row per task unit and context/actionable-feature query.
- Result: `POSITIVITY_GATE_FAILED`; FCI was not executed.
- Claim readiness: `paper_ready` as a bounded no-support result; `blocked` for
  any claim that FCI selected an effective intervention.

## Results

| Scope | All task units | Context present | Context absent | Context unresolved | Feature present | Feature absent | Shared-state lineages |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CWE-328 / current cryptographic hash | 25 | 13 | 3 | 9 | 0 | 13 | 0 |
| CWE-611 / external-entity control | 13 | 9 | 3 | 1 | 5 | 4 | 0 |

All five CWE-611 `PRESENT` states came from SeCodePLT. All four `ABSENT`
states came from SALLM or SecurityEval. Manual evidence-span review confirmed
that the five positive Prompts explicitly prohibited or restricted external XML
entities. The gate therefore fails because the feature state is also a source
lineage indicator, not because the extractor failed to find the visible
requirements.

The CWE-328 context contained no Prompt that required a current cryptographic
hash. Prompts that mentioned a user-selected algorithm, generic cryptographic
hashing, or an example set containing both MD5 and SHA-256 were correctly not
promoted to `feature.current_cryptographic_hash=PRESENT`.

The development sensitivity also fails: CWE-611 has enough raw state counts at
the relaxed threshold but no shared lineage; CWE-328 has no positive state.
Running FCI would therefore turn dataset authorship into an apparent mechanism
signal. The frozen gate correctly stopped before any causal graph or selector
ranking was produced.

## Protocol risks

- **Source-proxy confounding:** CWE-611 feature state is perfectly separated by
  source lineage in this pilot.
- **Insufficient support:** neither query meets formal state-count thresholds.
- **Scope limitation:** only two outcome-blind scopes were run; this does not
  establish that every catalog feature lacks natural variation.
- **Extractor measurement:** one LLM extractor was used, and unresolved context
  semantics remain explicit.
- **Runtime mismatch:** remote Python 3.13.12 is outside the supported 3.12
  reviewer environment.
- **No outcome:** this pilot intentionally cannot report association, FCI rank,
  ConfirmedYield@K, or intervention effect.

## Decision

The protocol correction is retained: discovery uses natural, unmanipulated
Prompts, while ADD and REMOVE keep separate source-state rules. The pilot does
not authorize FCI scale-up on the current corpus.

Before FCI can remain the focal selector, a new outcome-blind discovery source
must provide both feature states within the same task context and overlapping
lineages. Otherwise the conservative successor is to use Prompt TSG for
context/feature binding, preregister a finite catalog hypothesis set, and make
held-out randomized intervention effects the primary study. Randomly creating
feature states would be a separately labeled randomized-discovery design, not
observational FCI.

