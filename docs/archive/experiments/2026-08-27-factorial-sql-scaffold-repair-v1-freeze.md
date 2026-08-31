# Factorial SQL scaffold-repair follow-up v1 freeze

**Evidence status:** prospectively specified and implementation-tested; provider outcomes do not yet exist  
**Study:** `factorial-sql-scaffold-repair-qwen35-v1`  
**Predecessor evidence:** `factorial-sql-confirm-qwen35-v3`

## Why this is a separate follow-up

The predecessor confirmation completed 240 assignments and found a zero primary
interaction. Its A00 secure yield was already 96.7%, because Qwen3.5 generally
implemented both SQL controls when generating from scratch. The aggregate ceiling
motivated a different generation context: completing an existing implementation whose
SQL construction contains both uncontrolled identifier interpolation and direct value
interpolation.

The predecessor result remains immutable. This follow-up has new prompt and task IDs,
a new corpus digest, new seeds, a repair-specific generator instruction, and a new
study ID. It retains exactly the same 30 task units. No task-specific predecessor
outcome was used to include, exclude, or weight a task. A favorable result may support
a context-conditioned repair-policy claim; it cannot turn the predecessor null into a
positive result or establish universal mechanism synergy.

## Population and scaffold qualification

The corpus is `data/method/factorial-sql-scaffold-repair-v1`, with bundle digest
`bade1da48befac94873ea46465d98befc36a29ce3d012266c7ba098cd75e893f`.
Its 30 task-unit IDs are exactly the predecessor set, while all 30 task IDs are new.

Each task contains a deterministic, syntactically valid Python DB-API starter
implementation. The source prompt does not label the starter as insecure or vulnerable.
It instructs the model to preserve the API, operation, result semantics, and existing
SQL construction unless an `Additional constraints` statement requires a change.

Before any provider call, all 30 starters were checked with the same frozen Oracle
profile used for outcomes. Every starter is:

- valid Python;
- Oracle-evaluable;
- `unsafe` for value parameterization; and
- `unsafe` for finite-domain identifier control.

This is a qualification of the designed input manipulation, not a generated-code
outcome and not a task-selection rule.

## Frozen factorial policy

The pair and four assigned cells remain unchanged:

| Cell | Value handling policy | Identifier handling policy |
| --- | --- | --- |
| A00 | preserve starter behavior | preserve starter behavior |
| A10 | require driver value binding | preserve starter behavior |
| A01 | preserve starter behavior | require finite-domain control |
| A11 | require driver value binding | require finite-domain control |

Both factor orders retain equal probability. One outcome-blind intervention transaction
materializes all four variants for each task and order, followed by blinded cross-cell
validation. The code generator is `qwen3.5-flash-2026-02-23`; the Functional Judge is
the frozen non-thinking Qwen3.7-Max evaluator after AST/compile validation.

The formal scale is:

`30 task units x 2 orders x 4 cells = 240 assignments`.

## Outcomes and analysis

The primary outcome remains Oracle-evaluable secure-code yield. The primary estimand
remains the two-sided risk-difference interaction:

`delta = mu11 - mu10 - mu01 + mu00`.

The frozen max-|T| family uses 5,000 task-unit bootstrap draws at familywise alpha
0.05. Factor-1, factor-2, and A11-A00 joint effects are secondary. The practical
interaction margin is 0.20; maximum unknown fraction is 0.10; and the A11-A00
functionality non-inferiority margin is 0.10.

The Oracle's assignment-level `value_parameterization` and `identifier_control` traces
are predeclared diagnostics. Their cell rates are independently recomputed, but they
are not causal mediators, primary outcomes, eligibility variables, or denominator
filters.

Because the full-security endpoint is conjunctive, a positive interaction is interpreted
as a joint prompt-policy interaction in this repair setting. It is not, by itself,
evidence of a universal biological-style or software-mechanism synergy.

## Scale-up gate

A separate four-task-unit development corpus covers ordering, filtering, updating, and
aggregation scaffolds. It is disjoint from the 30 formal task units and authorizes no
scientific claim. The full run may start only after this 32-assignment canary closes all
assignments, preserves Oracle evaluability, demonstrates that the two target statements
can be implemented separately, and does not reveal a systemic functionality failure.

The full population, treatment statements, model, Oracle, outcome, analysis family,
practical margins, and task-unit retention rule are frozen before that canary is run.
