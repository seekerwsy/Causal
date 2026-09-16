# Proportional academic prototype: source, intervention and Oracle

Date: 2026-09-10. Status: **executed development check, no scientific effect result**.

Follow-up: the later [rapid inclusion pass](2026-09-10-rapid-dataset-inclusion.md)
has now materialized broad pool membership and reused existing three-axis source
evidence. The account below records the preceding three-task prototype step.

The owner authorized relaxing the discussed source and Oracle constraints,
updating project instructions, and continuing the next development step. The
active protocol remains `SPECIFIED_DRAFT`. This check used no providers, generated
no model code, consumed no protected evaluation tasks, and assigned no formal roles.

## Method decision

Source screening now asks whether the source supports the proposed comparison:
relevant context, operation/security boundary, and non-target invariants. An
incomplete full functional specification is not an automatic barrier to an
independently measurable security-policy endpoint. Unknown complete functionality
and joint success remain unknown.

For explicit prompt-requirement interventions, absence means that the complete
prompt does not express that requirement. It does not assert absence of security
in generated code. Ambiguous or implicit requirements remain unresolved. Exact
target, No-op, placebo and generic wording belongs to intervention design, not
natural-source quality. Oracle qualification covers the actual endpoint and
admitted code forms; unused languages and profiles do not block a narrower scope.

These rules are in `AGENTS.md` and protocol Sections 4.1, 19 and 24.7. The seven
stages, RQs, assigned-arm task-unit ITT, arm families, multiplicity, role firewall,
unknown handling and formal authorization boundary are unchanged. Pair retains
its own joint-context and four-cell requirements without Atomic heredity. An
internal mechanism trace is required for the stronger mechanism interpretation,
not universally for a reproducible policy-only endpoint.

The old 1,482 source-candidate reviews used five axes and yielded 11 fully
supported Atomic combinations. Their frozen rule and interpretation are retained.
They have not been rescored, and this revision establishes no new population
capacity. The existing source-use builder/verifier remain the reproduction path
for that frozen preparation. The new source principle has been examined manually
on development examples; population-wide automated screening and its extractor
qualification have not been implemented or executed under the revised meaning.

## Bounded next step and findings

Only previously exposed `QUAL_DEV` source material was inspected. The prototype
uses the earliest task ID in each of three Python families, SQL, XML and TLS.
This is a deliberate development contrast, not a random or representative sample.
One author reviewed source meaning; there was no independent source qualification.
All exact source prompts, role and source hashes, judgments, SQL variants and
pre-execution probe expectations are in
[the development input](../../data/method/explicit-requirement-development-v1.json).

| Source task | Development finding | Measurement consequence |
|---|---|---|
| `remove_user(username)` | The fixed `users` deletion and caller-supplied value are interpretable; parameter binding is not expressed. | A parameterization ADD comparison can be drafted without assuming unsafe baseline code. Three task-shaped probes return secure, insecure and unknown as expected. |
| `get_root()` parsing `resources/config.xml` | Entity-resolution configuration can be considered separately from unspecified return-object details. | The existing XML profile reports secure for an explicitly entity-enabled parser with a fixed local file. It cannot measure the proposed configuration endpoint as-is. This is not evidence of an exploitable vulnerability in the task. |
| `get_ctx()` creating an SSL context | Context creation is interpretable, but purpose and connection use are unspecified. | The use-site TLS profile correctly returns unknown for a returned context with no connection. Source usability does not establish endpoint coverage. |

For SQL, all four existing ADD arms now have exact draft texts:
`TARGET_PATCH`, `NOOP_REWRITE`, `LENGTH_MATCHED_PLACEBO`, and
`GENERIC_SECURITY_REMINDER`. Each preserves the original source byte-for-byte
and adds an implementation note; the No-op restates the original operation.
Target and placebo additions each contain 19 whitespace-delimited words. This
checks a development matching rule only. Model-token matching or another formal
length metric, semantic validation of controls, and extractor qualification are
still pending. The source leaves commit, return and exceptional behavior partly
unspecified, so these drafts do not confer complete functional qualification.

`qualify_target_security_profiles` and the existing qualification command now
accept an explicit profile scope. The report lists qualified and unqualified
profiles, retains secure/insecure/unknown checks, and fails on missing boundary
labels or label errors. Omitting scope retains the full-catalog replay behavior.
The SQL-only qualification evaluated **4 existing gold cases, all matched**;
33 supplied cases from unused profiles were outside the declared scope.
This is a bounded profile check, not an estimate of general detection accuracy.

The separate task-shaped static probes evaluated **6 examples**: SQL **3/3**
matched, XML **1/2** matched, and the TLS unknown case matched. The XML mismatch
is retained in the result. Only SQL proceeds in the current prototype scope;
no XML or TLS measurement qualification was issued by this check. There are
no model outputs, assigned arms, treatment effects or inferential tables.

## Reproduction and evidence

Environment: Windows, Python 3.12.13, the previously prepared clean reviewer
environment at `.tmp/sequential-source-review-20260909/final-reviewer-env`.
Commands below explicitly import the current source tree. They do not rely on
the older installed package in that environment. No new environment or deployment
workflow is needed.

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
$prototypePython = '.tmp/sequential-source-review-20260909/final-reviewer-env/Scripts/python.exe'
& $prototypePython -m prompt_mechanism_study.cli qualification target-security-oracle data/method/phase-context-policy-v3-mechanism-registry-v1.json .tmp/replay-sql-oracle --cases data/oracle-calibration/prompt-tsg-security-profiles-v2-cases.json --profile python.cwe89.sql_values.v1
& $prototypePython -m pytest tests/test_security_profiles.py tests/test_representation.py -q -p no:cacheprovider --basetemp=.tmp/replay-proportional-tests
```

Focused verification: **30 passed, 17 deselected** under the reviewer marker.
Checks cover scoped qualification, retained error and unknown boundaries, the
unchanged full-catalog qualification, and operation-source eligibility. The
existing seven-stage smoke and full-source replay were unaffected and were not
rerun. No claim of a new clean installed release is made.

The saved outputs are the
[SQL qualification](../../data/method/explicit-requirement-development-v1-sql-oracle/qualification.json)
and [development report](../../data/method/explicit-requirement-development-v1-check/report.json),
with [all probe decisions](../../data/method/explicit-requirement-development-v1-check/probe-results.json).
The report binds the input digest, exact measurement producer, environment,
qualification manifest and limitations. The small replay below independently
checks source identity, SQL text construction and recorded labels without writing
over any output or executing the snippets:

```powershell
@'
import json
from pathlib import Path
from prompt_mechanism_study.artifact_io import read_json, file_sha256, verify_bundle
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.target_security_profiles import evaluate_target_security_profile, target_security_profile_producer_sha256
input_path = Path('data/method/explicit-requirement-development-v1.json')
plan = read_json(input_path)
saved = Path('data/method/explicit-requirement-development-v1-check')
verify_bundle(saved)
report = read_json(saved / 'report.json')
assert report['input_sha256'] == file_sha256(input_path)
assert report['producer_sha256'] == target_security_profile_producer_sha256()
source = Path('data/dataset-curation/reviewer-task-unit-dataset-v5')
assert file_sha256(source / 'manifest.json') == plan['source_manifest_sha256']
assert file_sha256(source / 'task-roles.jsonl') == plan['source_roles_sha256']
roles = {r['task_unit_id']: r for r in map(json.loads, (source / 'task-roles.jsonl').read_text().splitlines())}
tasks = {r['task_unit_id']: r for r in map(json.loads, (source / 'task-units.jsonl').read_text(encoding='utf-8').splitlines())}
for row in plan['source_reviews']:
    assert roles[row['task_unit_id']]['data_role'] == 'QUAL_DEV'
    assert row['source_prompt'] == tasks[row['task_unit_id']]['model_visible_input']['natural_prompt']
    assert content_hash(row['source_prompt']) == row['source_prompt_sha256']
sql = next(r for r in plan['source_reviews'] if r['family'] == 'sql')
for arm, prompt in plan['sql_arm_variants'].items():
    assert prompt == sql['source_prompt'] + '\n    # Implementation note: ' + plan['sql_arm_notes'][arm] + '\n'
    assert content_hash(prompt) == plan['sql_arm_prompt_sha256'][arm]
assert len(set(plan['sql_arm_variants'].values())) == 4
assert len(plan['sql_arm_notes']['TARGET_PATCH'].split()) == len(plan['sql_arm_notes']['LENGTH_MATCHED_PLACEBO'].split()) == 19
cases = plan['measurement_probes']
results = read_json(saved / 'probe-results.json')
assert len(cases) == len(results) == 6
for case, row in zip(cases, results, strict=True):
    actual = evaluate_target_security_profile(case['code'], case['profile_id'])
    assert case['case_id'] == row['case_id'] and case['expected_label'] == row['expected_label']
    assert actual['security_label'] == row['actual_label']
    assert actual['decision'] == row['decision']
    assert row['matched'] == (row['actual_label'] == row['expected_label'])
assert sum(not r['matched'] for r in results) == report['probe_mismatches'] == 1
print('Source identity, four SQL draft arms and six saved probe decisions reproduced.')
'@ | & $prototypePython -
```

The next research unit is the SQL explicit-requirement policy: qualify its
source-only representation and complete its independent intervention/functional
review before a prospectively authorized model experiment. XML endpoint repair
and TLS constructor measurement are separate optional scope extensions. The
current findings do not justify another full-corpus cleaning round or qualifying
unused Oracle profiles.
