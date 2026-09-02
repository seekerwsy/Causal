# Prospective role, power, and budget decision support — 2026-09-02

**Status:** `DECISION_SUPPORT_ONLY_NOT_A_FREEZE`

This note reconciles the final v5 source population with the existing
outcome-blind power and provider-budget implementation. It reads no Prompt-TSG
output, selector result, generated code, arm, Oracle result, or experimental
outcome. It authorizes zero provider calls and does not assign a formal data
role.

## Result

The conservative candidate design remains scientifically coherent but cannot
yet be frozen against the current 21-CWE population. Its proposed coordinates
are:

- Core RQ1 only: Atomic Full versus RD-only and Pair Full versus No-Relation;
- one fixed `qwen3.7-flash-2026-07-15` model coordinate;
- `K_A=5`, `K_I=3`;
- practical margins `0.05/0.05`, two-sided alpha `0.05`, target power `0.80`;
- two global realizations, one realization per task-policy coordinate, and two
  request slots per arm;
- planning effects of 0.20 and 0.25 over baseline oracle-evaluable secure-code
  yield 0.30, with the remaining assumptions documented in
  `rq1_worst_case_budget.md`.

At the more conservative 0.20 effect, the checked rounded design uses 100 task
units per Atomic effect and 170 per Pair effect. The production simulator and
independent implementation both replay:

| Track | Max-|T| family bound | Task units/effect | Minimum power | 95% Monte Carlo half-width | Verification |
|---|---:|---:|---:|---:|---|
| Atomic | 10 | 100 | 0.8215 | 0.00751 | `TARGET_POWER_SIMULATION_VERIFIED` |
| Pair | 6 | 170 | 0.8082 | 0.00772 | `TARGET_POWER_SIMULATION_VERIFIED` |

These are assumption-conditional planning results, not observed effects. The
corresponding result IDs are
`target_power_simulation_result_8f92647a42149d930ebbb19de4d74a9754db775d14373e528f50e0db151cc587`
and
`target_power_simulation_result_cf1ee7df3cb026c5b880b6afcecf8d32834916a6a61c3c58b8330cdbfd274d82`.

## Final-v5 role capacity

The authoritative source is
`data/dataset-curation/reviewer-task-unit-dataset-v5`, bundle SHA-256
`33ab47c3b7f40f9a66a008460510e50c8a9afbda08ec951aab1d400e6cda93da`.
The scope mapping is the 21-CWE Python layer in
`data/dataset-curation/phase-context-policy-v3-eligibility-policy-v1.json`.
The two qualification reservations are the source-only candidate bundle with
manifest SHA-256
`1912f9c5cad5d43ddfdc44aff688c3eee62891184dc39aa6bb7e1a61ab4860ff`.

| Population step | Task units |
|---|---:|
| Final quality-included Python source population | 381 |
| In the current 21-CWE Python layer | 227 |
| Current-layer method-exposed, therefore unavailable to fresh formal roles | 16 |
| Current-layer source-curated and prospectively unassigned | 211 |
| Reserved as source-only `QUAL_DEV`/`QUAL_ACCEPT` candidates | 56 |
| Current-layer source-curated units left for Discovery plus Confirmation | 155 |

All 211 current-layer unexposed units and all 155 residual units have distinct
near-duplicate groups. The residual family capacity is:

| Family | Included | Unexposed before qualification reservation | Reserved | Residual |
|---|---:|---:|---:|---:|
| Injection/interpreter | 95 | 91 | 27 | 64 |
| File/parser/external resource | 76 | 67 | 15 | 52 |
| Identity/authorization/permissions | 29 | 28 | 3 | 25 |
| Cryptography/randomness/integrity | 27 | 25 | 11 | 14 |

Technical readiness is not an admission rule, but it exposes the immediate
measurement workload: 101 current-layer units are currently marked ready; 14
are method-exposed and 28 are in the two qualification reservations, leaving 59
ready residual units. Missing Oracle/binding support therefore cannot be
treated as already recovered.

The decisive count is `155 < 170`. The current population cannot allocate a
170-unit Pair-confirmation role and even one disjoint Discovery unit after the
candidate qualification reservations. More importantly, a 170-unit named role
would not prove that every selected Pair has 170 eligible task units; the later
hypothesis-specific support and power Gate remains mandatory.

## Bounded alternatives

1. **Recommended scientific path:** retain the 0.20 planning effect and
   `K_A=5`, `K_I=3`; recover existing Oracle/binding capacity and add independent
   current-scope capacity before the five-role manifest is frozen. The absolute
   arithmetic shortfall is 16 units for a nonempty Discovery role, 75 for a
   60-unit Discovery pool, and 115 for a 100-unit Discovery pool. These are
   lower bounds, not an acquisition target; the qualified coverage profile and
   candidate-specific eligibility can require more.
2. **Narrow Pair family:** `K_I=1` needs about 130 Pair task units under the same
   assumptions, leaving only 25 current-scope units for Discovery. This changes
   the fixed-slot RQ contract and is not recommended merely to fit the current
   census.
3. **Larger detectable effect:** retaining `K_I=3` but planning only for a 0.25
   Pair effect needs about 100 task units, leaving 55 for Discovery. This is a
   materially weaker sensitivity contract and requires explicit prospective
   author approval; it cannot be selected because it is cheaper.
4. **Prospective scope extension:** 71 additional unexposed tasks match the
   already listed priority-extension CWEs. They can close the raw count gap but
   require new mechanism, representation, and Oracle qualification. They are
   not silently interchangeable with the current 21-CWE population.

No option permits D0 Discovery supplementation to stand in for Confirmation
capacity. The two populations and their acquisition rules remain separate.

## Exact provider envelope for the conservative candidate

Using the already recorded candidate maximum unit costs of CNY 0.004916 for
materialization, 0.004096 for generation, and 0.002458 for the functional
judge, `rq1_worst_case_budget_envelopes` gives:

| RQ1 envelope | Materialization | Generation | Judge | Total calls | Maximum cost |
|---|---:|---:|---:|---:|---:|
| Core | 4,040 | 16,160 | 16,160 | 36,360 | CNY 125.773280 |
| Core + Expert | 6,060 | 24,240 | 24,240 | 54,540 | CNY 188.659920 |
| Core + Expert + Random | 8,080 | 32,320 | 32,320 | 72,720 | CNY 251.546560 |

This envelope has ID
`rq1_budget_envelope_2271756bab8d848b339baa7c99a4bb3956b908906e9a4a734ccd4ff19af79ac0`.
It assumes no selector-overlap credit and zero hidden retries. For the proposed
Core design, CNY 200 is a sufficient author-facing cap candidate; if every
implemented baseline is formally selected, the corresponding cap candidate is
CNY 300. Neither amount is authorized here. The former CNY 1,000 suggestion is
unnecessary for this exact fixed envelope and must not be copied into a freeze.

## Next gate

The immediate external dependency remains independent completion of both
source-only gold files. In parallel, the author can approve the conservative
coordinates above and choose the population route. Formal role membership,
the integrated one-shot acceptance plan, and any provider call remain blocked
until the chosen route supplies a support- and power-feasible disjoint
population.

