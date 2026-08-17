# Five-CWE Gate B Reviewed-Placebo v1

## Scope

This stage repairs the intervention-protocol failure observed in the first CWE-502 Gate B
micro-run and prepares one bounded five-CWE Gate B run. It does not generate code, evaluate an
outcome, or authorize a scientific claim.

The source Gate A bundle is
`data/e2e-pilot/five-cwe-discovery-gate-a-qwen7b-v2`. The five-CWE expansion selects one frozen
discovery task from each of CWE-78, CWE-89, CWE-502, CWE-328, and CWE-338. The planned live run
contains five source extractions, twenty LLM intervention calls, and twenty blind variant
extractions, for a total budget of 45 provider calls.

## Preserved CWE-502 history

The first live CWE-502 attempt is preserved on the experiment server at
`/home/ubuntu/secaware-experiments/gate-b/five-cwe-cwe502-micro-20260818-01`. All nine planned
provider calls completed, and all four arm-level semantic validations passed. Its final placebo
length gate failed because the intervention model returned the unchanged source Prompt for the
placebo arm. The target suffix was 60 characters and the placebo suffix was empty. This isolates
the failure to placebo execution rather than the target intervention, blind extractor, or CWE-502
Oracle profile.

The separately authorized repair and revalidation ran from deployment
`/home/ubuntu/secaware-deployments/five-cwe-gate-b-repair-20260818-14` under Python 3.12.13.
Canonical server copies and repository copies use the following names:

- `five-cwe-cwe502-placebo-repair-20260818-01`: one attempted and one accepted provider response,
  zero errors, and zero validation failures. The reviewed 55-character suffix passed the frozen
  54--66 character interval.
- `five-cwe-cwe502-revalidation-20260818-01`: five attempted and five accepted blind extraction
  responses, four validated intervention arms, zero errors, and zero validation failures.

The target arm changed only `safety.safe_deserialization` from absent to present. The generic arm
changed only `safety.generic_security_reminder`. The no-op and placebo arms changed no registered
task or safety feature. All copied artifacts were rechecked against their manifests: 10/10 repair
files and 26/26 revalidation files matched their recorded SHA-256 values.

## Scale-up policy

A single fixed placebo sentence is not length-compatible with every target mechanism. The frozen
Gate A target additions are 32, 41, 55, 50, and 52 Unicode characters for CWE-328, CWE-338,
CWE-502, CWE-78, and CWE-89 respectively. The batch policy therefore uses a finite reviewed bank
of four natural, presentation-only suffixes with lengths 33, 43, 55, and 60 characters.

For each task, Gate B executes the target and no-op arms before the placebo arm. It then selects the
registered suffix with the smallest absolute length difference among suffixes passing the existing
`unicode-chars-relative-10pct-min5-v1` contract. Ties preserve registered bank order. The bank and
order are content-addressed in the intervention policy. The LLM must copy the selected suffix
character-for-character; source-prefix preservation, exact suffix equality, the quantitative
length gate, AllowedDelta, sentinel neutrality, and independent blind extraction all remain hard
gates. If no registered suffix fits, or the LLM does not execute it exactly, Gate B reports an
error before outcome generation. No additional handwritten security-recognition rules are added.

The zero-provider five-CWE check selected suffix lengths 33, 43, 55, 55, and 55 for the five frozen
target additions; every selection passed its task-specific interval. The implementation and
adjacent intervention checks passed 115 targeted tests. Ruff 0.12.12 formatting and static checks,
Python compilation, configuration loading, and `git diff --check` also passed.

## Execution issues retained

- The first local test command omitted the worktree `src` directory from `PYTHONPATH`; collection
  stopped before tests ran. The corrected command used the fixed repository Python environment and
  explicit worktree `PYTHONPATH`.
- Ruff is not installed inside the fixed runtime virtual environment. Formatting and static checks
  were rerun through the repository's previously used pinned `uvx --from ruff==0.12.12` entry.
- One combined preflight command used a Linux here-document in PowerShell and failed during parsing,
  before any formatter, test, or experiment action began. The rerun used a PowerShell here-string
  piped to the fixed Python interpreter.
- A broad file search passed shell wildcards that PowerShell did not expand for `rg`; the search was
  repeated with explicit repository paths. This did not affect code or experiment outputs.

These issues are environment-command errors, not accepted test or experiment results, and are
recorded here to prevent repetition.
