# Outcome-blind security-scope preflight

**Status: development preflight, not formal admission.** The active protocol is
still `SPECIFIED_DRAFT`. This note uses source metadata and already exposed
development material to decide what needs qualification next. It does not assign
Discovery or Confirmation roles, select tasks by generated-code results, change
the primary endpoint or revise historical labels.

## Source support, before looking at code outcomes

Run `python scripts/scope_inventory.py` from the repository root after installing
the package. The command verifies the bundled v4 manifest and recounts task-unit
identities and prior Atomic source screens. Input:
`data/dataset-curation/research-candidate-pool-v4` (1,954 task units, 684 Python).
The source CWE is metadata for stratification, not a policy, a TSG requirement or
an FCI variable.

| Source label | Python task units | Units with a prior Atomic screen | Units with at least one source-supported screen | Supported task-policy rows |
| --- | ---: | ---: | ---: | ---: |
| CWE-78, command injection | 67 | 42 | 0 | 0 |
| CWE-502, deserialization | 50 | 32 | 10 | 20 |
| CWE-89, SQL injection | 28 | 18 | 6 | 12 |
| CWE-22, path traversal | 15 | 4 | 0 | 0 |

The screens reuse an older, limited policy book. Zero supported screens therefore
does **not** prove zero legitimate interventions. The 20 CWE-502 rows represent
ADD and REMOVE records for ten tasks: five tasks refer to safe JSON parsing,
four to safe YAML parsing and one to SQL value parameterization. The latter is a
concrete example of why source CWE labels cannot define policy identity. The
12 CWE-89 rows are ADD/REMOVE records for six tasks, not twelve independent
tasks or twelve qualified edits. Every row still says intervention qualification
is pending; formal admissions are zero. These counts cannot serve as sample-size
or FCI-positivity guarantees.

The older [paper inventory](../paper/fse2027/tables/cwe-inventory/README.md)
uses v2, with 722 Python tasks and 80/52/33/23 under these labels. V4 applies
later exposure boundaries, leaving 67/50/28/15. Neither snapshot certifies
independent evaluation capacity; the v4 pool retains source prompts for
preparation, while later exposure and near-duplicate exclusions still matter.

## Oracle support on actual generated code

The existing Python AST profiles for command execution, deserialization, SQL
values/identifiers and path confinement have secure, insecure and unknown gold
controls in `data/oracle-calibration/prompt-tsg-security-profiles-v2-cases.json`.
The saved v3 qualification matches its 43 gold controls across its full registered
scope. These are implementation checks on selected idioms, not estimates of
accuracy or coverage on future generated programs.

As a code-form diagnostic, we replayed the current target-only AST profiles on
unchanged, already exposed code from the 2026-09-22 automatic-policy pilot,
preserved on branch `codex/pre-artifact-scope-20260923` at `f1cd0011`, path
`data/method/local-full-chain-v1/automatic-policy-pilot`. That pilot used a
different, limited behavioral endpoint. This comparison therefore reveals
**measurement-definition differences**, not a new gold-standard adjudication:

| Pilot endpoint | Independent tasks / saved code | Earlier behavior label | Current AST profile on the same code | Implication |
| --- | ---: | --- | --- | --- |
| Command data boundary | 1 / 12 | 12 secure | 12 secure | Agreement in one narrow case; no evidence of effect variation. |
| SQL data boundary | 2 / 24 | 24 secure | 24 insecure (`dynamic_identifier_allowlist_not_proved`) | Existing static rule and pilot behavior witness do not measure the same claim reliably enough to exchange labels. |
| Source-directory boundary | 2 / 24 | 15 secure, 9 insecure | 16 insecure, 8 unknown | AST coverage differs from the behavioral endpoint and varies by arm: unknown is 2/8 No-op, 2/8 Target and 4/8 Generic. |

The SQL and path counts include repeated arms and seeds; their independent task
counts are two each. The pilot has no deserialization generation at this scope,
so its generated-code Oracle coverage remains unmeasured. Its own report also
documents an XML functional-test counterexample. Neither the pilot witness nor
the AST result should silently replace the other, and these old outputs are not
rescored as a new effect experiment.

## Decision for the next bounded development check

No one of these four CWE labels is yet a formally qualified study scope. First,
resolve the SQL definition on the two exposed generated-code tasks: separate
data-value binding from dynamic identifier handling, then decide which property
can be tested with a fixed, task-compatible witness. Retain all 24 old labels
under their original rules. Second, use exposed path and deserialization cases
to establish exact task boundaries and representative safe/insecure/unknown code
forms; the current screens alone cannot identify independent ADD opportunities.
Command execution has one exposed generated-code task and no prior supported
source screen in this pool, so it needs task support before effect estimation.

For any endpoint subsequently admitted, freeze its task frame, policy meaning,
Oracle environment and interpretation of unknown **before** generating new
comparison outcomes. Qualify only the actual language, task family and code
forms used. Report assignment-level code validity, secure/insecure/unknown,
Oracle coverage by arm, original-task functionality and joint success separately.
The primary secure-code yield remains assigned-arm task-unit ITT; unknown
contributes no observed secure yield but is never relabeled insecure. Existing
functional judgments are retained with their evidence and limits, not used as
post-assignment exclusion. A candidate's unrelated unresolved TSG content does
not block it; unresolved meaning in its target, condition or required non-target
behavior does.

Once a measurable scope has independent task support, the complete method still
needs candidate construction, prioritization, hypothesis freeze, randomized
comparison and independent table replay. A fixed-policy test establishes that
policy's effect within its declared scope; it does not by itself establish an
increment from automatic TSG construction or FCI selection.
