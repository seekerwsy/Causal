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
Gate A target additions; every selection passed its task-specific interval. The implementation and
adjacent intervention checks passed 115 targeted tests. Ruff 0.12.12 formatting and static checks,
Python compilation, configuration loading, and `git diff --check` also passed.

## First five-CWE live attempt

`five-cwe-gate-b-balanced-20260818-01` is retained as a failed scale-up attempt. It completed 15
intervention calls and 20 extractor calls: all five source extractions, all four arms for CWE-338,
CWE-502, and CWE-89, plus the target, no-op, and generic arms for CWE-78. All completed arm-level
validations passed. The run stopped before sending the CWE-78 placebo because the live target suffix
was 78 characters, including the model's natural newline and indentation, while the longest
registered placebo suffix was 60 characters. The frozen interval was 70--86 characters. CWE-328
was not yet processed. Thus 35 responses are reusable and 10 calls remain.

The resume configuration adds one reviewed 73-character presentation-only sentence and otherwise
keeps the same task set, app configuration, arm contracts, and request-policy version. The previous
run is used only through exact request-byte matching. The five source responses and 15 accepted
variant pairs must be reused; only the new CWE-78 placebo pair and four CWE-328 arm pairs may call
the provider. The expected resume accounting is therefore 35 reused calls and 10 live calls.

`five-cwe-gate-b-balanced-resume-20260818-02` passed the CWE-78 length preflight and exact placebo
execution. It reused 35 calls, completed the new CWE-78 placebo intervention and extraction, and
then stopped on the CWE-328 target arm. The target executor inserted “collision-resistant hash”
inside the original task sentence instead of preserving the original Prompt as an exact prefix.
The source-prefix gate rejected this response before blind extraction. This attempt contains 17
intervention pairs and 21 extractor pairs; 16 intervention pairs and all 21 extractor pairs are
valid for exact reuse. The one invalid CWE-328 target response is retained but excluded.

The second resume registers ` Use a collision-resistant hash.` as the exact append-only target
suffix only for the failed CWE-328 task. The request receives a separately versioned target-exact
policy marker and differs byte-for-byte from the rejected request, so the invalid response cannot
be reused accidentally. No system-template, feature catalog, AllowedDelta, extractor rule, or
source-prefix requirement is weakened. The expected accounting is 37 reused calls and eight live
calls: the corrected CWE-328 target pair plus its no-op, generic, and placebo pairs.

The first exact-target resume preflighted correctly but made zero provider calls. The reuse layer
found the retained invalid request under the same variant identity and correctly rejected the new
request-byte mismatch instead of silently falling through to a live call. The next configuration
therefore carries a single explicit reuse exclusion for that exact invalid intervention variant.
The exclusion list is validated against the selected Gate A variants, content-addressed in the
report, and recorded beside the new raw request. All original files remain present in the retained
failed run. This preserves fail-closed collision handling while authorizing the one intended live
replacement.

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
- The fixed server Python runtime does not contain `pytest`. Server configuration loading passed,
  but the optional duplicate server-side unit test did not start. The deployment was not mutated;
  the same commit had already passed the local fixed-environment targeted tests.
- The first five-CWE wrapper attempted to create sidecar logs inside a parent directory that did not
  yet exist. The Python runner still created and preserved its own command, environment, failure,
  raw request/response, and validation artifacts, but the three wrapper sidecars were absent. The
  operator observation records this packaging error and the exact 35/10 completed/pending counts.

These issues are environment-command errors, not accepted test or experiment results, and are
recorded here to prevent repetition.
