# SecAware v3 Framework Revision Log

**Timestamp:** 2026-08-20T02:34:11+08:00

**Mode:** `secaware-fse-paper` revise, preceded by an audit

## Input and Authority

- User instruction: revise the theoretical and methodological framework according to the second
  external review.
- Review source:
  `C:/Users/WuSiyu/.codex/attachments/c8480312-00d2-47d0-a933-ca466577518b/pasted-text.txt`
- Review SHA-256:
  `85df38fe844e83faa9a40f4d1a9ed7f6401d827dcdcafca8d706a3a1262929ed`
- Legacy specifications were read completely and retained without in-place edits.

## Revision Scope

The revision implements the review's four hard changes:

1. separate discovery and confirmation regimes and add an explicit intervention bridge;
2. split non-actionable context queries from one actionable feature;
3. repair the semantic-cluster hierarchy, realization-aware randomization, shared candidate universe,
   outcomes, estimands, estimators, multiplicity, and robustness rules; and
4. move JCI/RFCI to appendix scope and remove the expert study from the main-paper RQs.

It also adds the review-requested TSG well-formedness/query/rewrite semantics, background-knowledge
audit, request-randomness terminology, Oracle-support decomposition, and versioned migration rules.

## Final Contract Closure

Independent statistical, paper-conflict, and implementation-compatibility audits were run against
the draft. Their blocking findings were closed by:

- using one pre-randomization common-support task population for every evaluated model;
- defining context eligibility as `PRESENT` only and preserving the other three query states as
  distinct pre-outcome exclusions;
- requiring `ABSENT` as the ADD source state and a provenance-bound `PRESENT` clause plus an attested
  task-preserving neutral counterpart for REMOVE;
- separating task-independent `RealizationSpecRecord`s in `Q_h` from task-specific
  `TaskRealizationBundleRecord` arm texts;
- freezing one canonical block key that binds cluster, task, hypothesis, target, both realization
  records, model, and arm protocol;
- excluding selector identity and rank from hypothesis/bridge semantic identity;
- upgrading request, generation, Oracle, and outcome provenance around a nullable provider seed and
  a non-null request-randomness slot; and
- defining exact outcome states, cluster estimands, multiplicity families, selector bootstrap, and
  realization-robustness rules.

Compatibility follow-ups define sanitizer as a catalog-bound `GUARD` subsemantic for PromptTSG 2.1,
place context queries in a separately digested catalog, and require explicit v1/v2 migration tests.
The final independent statistical and implementation-compatibility rechecks reported no remaining
P0 or P1 findings.

## Files Added or Updated

- Added `docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`.
- Added `tests/paper/test_secaware_v3_framework_contract.py`.
- Updated `.agents/skills/secaware-fse-paper/SKILL.md` to read the successor specification.
- Updated `.agents/skills/secaware-fse-paper/references/causal-boundaries.md`.
- Updated `paper/AGENTS.md` with prospective v3 paper boundaries.

The already modified manuscript and its existing contract test were not overwritten. The legacy
dated specifications and all experiment artifacts were left unchanged.

## Validation Record

| Check | Result |
| --- | --- |
| combined targeted framework and paper contract tests | 11 passed |
| `quick_validate.py .agents/skills/secaware-fse-paper` | valid |
| tracked-file `git diff --check` and new-file trailing-whitespace check | clean; only Git LF/CRLF warnings |

Final framework SHA-256:
`6cf3184ed7c1d608015b927e8329d1f7be43dfc0ecc7699f62da81880ac4b87e`.

The first skill-validation attempt expanded an obsolete `CODEX_HOME` to `D:/skills/...` and failed
because the script was absent. The corrected run used
`C:/Users/WuSiyu/.codex/skills/.system/skill-creator/scripts/quick_validate.py` and passed. This path
failure did not affect any project file or result.

## Deliberately Not Performed

- No legacy artifact was migrated or reinterpreted.
- No implementation schema or experiment was changed in this revision.
- No quantitative paper result was inserted.
- The dirty manuscript was not rewritten before third-round framework approval.
- No full repository test suite or LaTeX build was run because the requested scope is the framework
  revision and its targeted contracts.
