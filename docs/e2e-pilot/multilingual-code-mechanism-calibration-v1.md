# Multilingual code-mechanism calibration v1

## Scope and blindness

- Date: 2026-08-19 (Asia/Shanghai).
- Worktree: `D:\MyCode\Causal\.worktrees\dataset-availability-audit`.
- Provider: Bailian OpenAI-compatible endpoint.
- Extractor model: `qwen3.5-flash-2026-02-23`, temperature 0, thinking disabled.
- Inputs contain only generated-style calibration code, language, target CWE, and a closed
  mechanism vocabulary. Prompt text, intervention arm, generator identity, Oracle/security label,
  and functional outcome are absent.
- The model emits sink/mechanism facts and code-line evidence. It does not emit the aggregate
  security label. A deterministic local projection produces the five-state mechanism value and
  binary `z_target_mechanism_realized`.

## Results

The five-call canary covered all five CWEs and Python/Java/Go/C. It completed 5/5 calls with zero
schema error and 5/5 expected mechanism directions.

The frozen twenty-case expansion completed 20/20 calls with zero schema error and 19/20 expected
directions (0.95 accuracy). Python, Java, and C were 5/5; Go was 4/5. The only disagreement was
`cwe78-go-safe-argument-vector`: the response classified
`exec.Command("ls", path).Output()` as `shell_execution_of_external_text`. Go `exec.Command`
executes the named program with a separated argument and does not invoke a shell by default, so the
expected state remains `proved_safe`.

This is a diagnosed semantic-criteria defect, not unexplained model variance. The v1 request listed
allowed mechanism tokens but did not define their operational boundary. Its artifacts and policy
digest remain immutable. A v2 policy will add finite definitions to the same fact vocabulary, rerun
the failed case plus adjacent CWE-78 controls, and only then replay the full twenty-case set. No
independent-validation code has been generated.

## Frozen artifacts

- `code-mechanism-multilingual-calibration-canary-bailian-20260819-01`
- `code-mechanism-multilingual-calibration-full-bailian-20260819-01`

Both directories contain effective configuration, environment, commands, every request and
response, parsed measurements, errors, progress, report, and artifact digests. No full repository
test suite was run.
