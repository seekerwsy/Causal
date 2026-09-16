# Research-artifact repair and verification — 2026-09-07

The authorized audit repairs use the single `phase-context-policy-v3` path.
The normative [protocol](../protocol.md)
and [reviewer guide](../reviewer-guide.md) now describe the same method. The
protocol remains `SPECIFIED_DRAFT`; this record establishes implementation and
reproduction behavior, not a formal study or a scientific effect. No external
LLM/provider calls, new task acquisitions or paper edits were made in this repair.

## Repaired scientific boundaries

All implementation paths below are relative to `src/prompt_mechanism_study/`.

| Audit issue | Final behavior and implementation | Verification |
|---|---|---|
| A smoke could be relabeled as formal evidence using arbitrary references | `selector_analysis.authorize_target_report` and `verification/reporting.verify_target_execution_artifacts` require the active author's frozen authorization, actual qualification/input references, raw execution records and measurement replay. `execution_artifacts.json` is explicit null for smoke. | Missing artifacts and package-created authorization fail; raw model/arm/task/prompt/seed, code, evaluator and outcome tampering fail. |
| TLS kwargs and later context mutation could be called secure | `target_security_profiles._tls_certificate_facts` tracks bounded ordered imports, literal/scalar/dictionary arguments, context aliases, property assignments and actual TLS use sites. Unresolved mutation, rebinding and control flow remain unknown. | Literal/dictionary `verify=False`, context mutation, aliases, scope and unknown cases; old producer qualification is rejected as stale. |
| One-realization execution conflicted with fully crossed estimation | `randomization.allocate_target_realizations` freezes one realization per task-policy before materialization. Failed bundles retain the original allocation and reason; they are not replaced. `inference._target_effect_work` estimates within realization then applies original `q_r`. | Replay of 7:3 allocation and failed bundles; unequal support with 1:1 and 1:3 weights; missing realization yields non-evaluable. |
| Bootstrap accepted draws below the frozen support minimum | `inference._target_family_bootstrap` jointly resamples whole task units within original source strata, preserves realization/cell weights and enforces the plan's cell and realization minima. | Independent draw enumeration distinguishes the required minimum of four from the former hardcoded two; `verification/effects.py` independently reconstructs estimates and families. |
| Power used a Gaussian proxy for the actual procedure | `study_design.simulate_target_power` generates categorical request outcomes and invokes the real weighted max-T family procedure; every non-evaluable replicate stays in the denominator. `verification/qualification.py` has a separate generator/estimator replay, called by budget and saved-result verification. | Multiple realizations, unequal weights, unknown/no-code outcomes, invalid families, exact inference-plan binding and tampered power statistics. |
| Discovery identity depended on outcomes | Atomic and Pair universes bind `preoutcome_data_sha256`; full observations have a separate scoring-data digest. Fold freezes also bind representation/covariate fields. | Flipping only outcomes preserves universe identity and changes scoring identity; changed pre-outcome fields fail freeze replay. |
| A selector could drift to another model | Atomic/Pair scoring and fold freezes in `prioritization.py` and `interaction_selector.py` require the plan to match every candidate's bound discovery model. | Both changed observation/plan models and a changed candidate model fail. |
| Baselines omitted part of common eligibility | `rq1_baselines.freeze_atomic_baseline_universe` and `freeze_pair_baseline_universe` consume Core's exact frozen discoverability/fold decisions. | Support-qualified but fold-ineligible Atomic candidates are absent from baselines; a legacy Pair support-only argument is rejected. |
| Zero candidates aborted the fixed-K path | Selectors, union, dispatch, measurement closure, inference and verifier accept a genuinely empty eligible union. Empty slots remain; no assignment or zero-valued effect is invented. | A complete seven-stage zero-discoverability reproduction has zero assignments/outcomes and preserves empty fixed slots. |
| Impossible endpoint combinations were accepted | `outcomes.Outcome` enforces binary endpoint domains, `secure <= evaluable <= valid`, terminal zeros and consistent latent/joint bounds. | Impossible and fractional/bool endpoint combinations fail construction and independent package reconstruction. |
| Global source counts were treated as candidate-level sample capacity | `qualification_data.summarize_source_role_capacity` verifies the frozen source/reservation bundles and uses only source quality, language, CWE routing, exposure and reservations. | Exact read-only census replay; no TSG, selector, intervention or outcome input. |

The existing Prompt TSG attribute-enum/schema repair was also verified in the
complete suite. Pre-existing representation-development changes and their failed
qualification record retain their own provenance.

The primary estimand is now the fixed-weight mixture
`sum_r q_r E[D_r | allocated r and protocolizable under r]`. It does not identify
wording differences on a shared population. Realization robustness labels,
context inference, secondary functionality non-inferiority and Pair response
labels remain inactive until their exact prospective rules and implementations
are frozen. Primary effects and all arm endpoints/bounds use the same weights.

The power simulator currently supports fully shared or disjoint family task
supports. Formal preflight rejects a partially overlapping support design until
its power model is qualified. The estimator itself retains partial-overlap
dependence. Preflight also rejects loss of planned task support after bundle
failure instead of filling the deficit with replacement tasks.

## Executed checks

The clean environment is Python **3.12.13**, Windows 11 build **26200**, in
`.tmp/research-repair-clean-env`. Its pinned installed packages are recorded in
[the environment requirements](2026-09-07-repair-requirements.txt), including
pytest 9.1.1, causal-learn 0.1.4.7 and NumPy 2.5.3. `pip check` passed. The stale,
ignored `src/secaware.egg-info` installation metadata was moved to
`.tmp/research-repair-obsolete-secaware.egg-info`; no source package or frozen
data was deleted for that cleanup.

Recreate the environment from the repaired working tree with Python 3.12:

```text
python -m venv NEW_ENV
NEW_ENV/Scripts/python.exe -m pip install -r docs/experiments/2026-09-07-repair-requirements.txt
NEW_ENV/Scripts/python.exe -m pip install --no-deps --no-build-isolation -e .
```

Executed commands, from the repository root:

```text
.tmp/research-repair-clean-env/Scripts/python.exe -m pytest -q -o addopts='' -p no:cacheprovider --basetemp=.tmp/research-repair-test16
.tmp/research-repair-clean-env/Scripts/prompt-mechanism-study.exe study smoke .tmp/research-repair-reference-smoke
.tmp/research-repair-clean-env/Scripts/prompt-mechanism-study.exe study verify-result .tmp/research-repair-reference-smoke
.tmp/research-repair-clean-env/Scripts/prompt-mechanism-study.exe study smoke .tmp/research-repair-reproduction-smoke
```

Use new output/temp directories for another reproduction. Saved reference
outputs are never overwritten. Final results:

- **238 passed in 129.94 seconds**, with no failures or skips, in the clean
  environment. The complete suite includes all 141 reviewer-selected cases.
- The final focused inference/execution-replay check also passed: **26 passed**.
- The complete seven-stage smoke and standalone saved-result verifier passed;
  the latter independently regenerated both power simulations as well as effects,
  families, budget, assignments and RQ tables.
- A second smoke reproduced **all 20 saved files byte-for-byte**, with the same
  bundle identity below.
- The source-capacity census replayed exactly; edited Markdown links, UTF-8
  text and `git diff --check` passed.

The source revision is Git HEAD
`848ed9ab9613d09ee5ad269e45ab003db4728477` **plus the repaired uncommitted working
tree**; HEAD alone does not contain the repair. The SHA-256 identity for the
Python source, tests, `pyproject.toml` and formal JSON configurations is
`9bcef9e493465cb5f625b203aeaa0cbfe50dd49d2fb602f92265cc0cb7801d36`.
It is SHA-256 of a UTF-8 JSON map from sorted POSIX relative paths to exact-byte
file SHA-256, serialized with sorted keys and separators `(',', ':')`.
The complete local file map and environment record are at
`.tmp/research-repair-environment.json`.

The current target Security Oracle producer identity is
`86d015225970a4bb28da70dc75ad91a4867ed90723db140560386413c9caf6d5`.
The existing frozen 43-case qualification retains its old producer identity.
Tests create temporary current-producer qualifications; they do not replace the
frozen qualification or establish new gold coverage.

## Saved reference and evidence limits

The seven-stage smoke writes 80 assignments, 80 measurements and 80 outcomes
across 20 synthetic task units. It makes zero provider calls. Its package is
`NON_CLAIM_TEST_ARTIFACT`, `evidence_level=tested`,
`scientific_claim_allowed=false`. The saved result bundle identity is
`5fdea23d5a041dd3888f0afe8b88c14c9c01fbca506c8baf3177cb7cf1af3c9c`.

The smoke uses ten tasks per effect, 1,000 simulation replicates and 100 bootstrap
draws. Its 0.01 acceptance threshold exists only to exercise accepted-package
plumbing. It is not a scientific power target. Under this synthetic fixture,
Atomic minimum coordinate power is 0.185 and Pair is 0.237. Respectively, 797 and
742 of 1,000 replicates have non-evaluable families and remain in the power
denominator. These figures demonstrate why this fixture cannot justify a formal
sample-size recommendation.

No full scientific reproduction is available: representation/measurement
qualification, the formal role manifest, candidate coverage and the scientific
power/budget freeze remain open. Formal provider execution and the positive
claim-authorization path have not been executed. Raw-artifact consistency and
local measurement replay are not cryptographic proof of a remote service event.

## Source capacity and removed planning documents

The census inputs are the immutable v5 source bundle, current eligibility policy
and source-review candidate reservations, with SHA-256 identities:

- Source manifest: `33ab47c3b7f40f9a66a008460510e50c8a9afbda08ec951aab1d400e6cda93da`.
- Eligibility policy: `8d8401ad3c1a45b295d4febdef8a5fb3f524e11b88f28e7a447afcd0b97792fb`.
- Reservation manifest: `1912f9c5cad5d43ddfdc44aff688c3eee62891184dc39aa6bb7e1a61ab4860ff`.

The exact census is `.tmp/research-repair-source-capacity.json`. It contains 381
quality-included Python source units, 227 in the current CWE scope, 211 unexposed
before reservations, 56 reserved and **155 residual units**. Residual source
families contain 64 injection/interpreter, 52 file/parser/external-resource,
25 identity/authorization/permission and 14 cryptography/randomness/integrity
units. These are upper bounds before candidate eligibility, split allocation
and power. They establish neither sufficiency nor a required acquisition count.

The former Gaussian-derived 100-Atomic/170-Pair sample sizes and CNY 200/300
formal-budget suggestions were removed from active planning; corresponding
formal recommendations are explicit null/blocked. The existing CNY 100
preexperiment approval is separate and unchanged.

Eight obsolete documents were removed: the seven development plans/inventories
under `docs/archive/development/` and
`docs/experiments/2026-09-02-role-power-budget-decision-support.md`. Their history
remains in Git. The active protocol, reviewer guide, and dataset contract were
reconciled. The former standalone phase-0 qualification register and budget
planning document were later removed with the Superpowers documentation tree;
their still-applicable constraints remain in the active protocol. Frozen run
bundles and historical outcomes retain their original bytes and interpretation.
