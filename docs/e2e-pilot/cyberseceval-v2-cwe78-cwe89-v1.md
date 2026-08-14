# CyberSecEval v2 CWE-78/CWE-89 engineering pilot v1

## Purpose

This is a small end-to-end engineering validation. It checks immutable input
construction, prompt-side extraction, real code generation, randomized
confirmation-arm plumbing, the single-pass functional judge, the independent
static Oracle, and provenance publication. It is not powered or approved for a
confirmatory causal claim.

## Frozen scope

- Dataset source: `cyberseceval_instruct_v2` only. Older exact duplicate copies
  in `cyberseceval_discover_adv` and `cyberseceval_secure_code` are excluded.
- Frozen split simulation seed: `20260810`.
- Discover: four independent tasks, two each for CWE-78 and CWE-89.
- Confirm: four independent tasks, two each for CWE-78 and CWE-89.
- Planned confirmation volume: at most 16 generations for one four-arm
  protocol per CWE scope. Any additional discovered protocol requires a new
  versioned configuration and budget review.
- Code generator: locally deployed Qwen2.5-Coder-32B-Instruct.
- Functional evaluator: one blind Ali Bailian Qwen3.5-Flash pass, seed 73001.
- Prompt extractor and intervention executor: deterministic catalog backends
  for this engineering validation. LLM backends remain separate experiment
  variants and are not silently mixed into this run.

## Interpretation boundary

All currently admitted CWE-78 and CWE-89 Oracle profiles have
`zero_finding_supported=false`. Analyzer findings may support an insecure
classification, but a zero-finding result remains `unknown_coverage`. Therefore
the pilot cannot estimate a secure-and-functional primary ITT effect. That
limitation is recorded as a gate, not converted into a secure label and not
hidden by handwritten fallback rules.

The four discover tasks also provide neither the sample size nor the natural
prompt-feature variation required for a substantive G-square FCI analysis. A
no-hypothesis discovery result is valid engineering evidence and must not be
replaced with intervention-derived observational rows.

Observed generation is restricted to `discover` prompts whose role is
`neutral_baseline`. Held-out confirm prompts are materialized only after frozen
randomization assignments through the separate confirmation planner. The first
mock feasibility run predates this isolation fix and is preserved as an
engineering diagnostic; its causal-table stage nevertheless included only the
four discover rows.

The first real-generator gate uses only the four discover baselines. Its
discovery command may terminate with the explicitly checked small-sample FCI
status after causal-table publication; that status does not authorize a
synthetic or manually injected hypothesis.

The first real run exposed a stale downstream coverage invariant: generation
and Oracle correctly covered four discover prompts, while causal-table assembly
still expected all twelve source prompts. The shared observed-eligibility
predicate now binds both request planning and causal-table validation. The
original failed execution record is retained and recovery adds only the missing
analysis stages from the already frozen code and Oracle artifacts.

## Reproduction

Build inputs into a new, non-existing output directory:

```powershell
$env:PYTHONPATH = "$PWD\src"
python scripts/build_e2e_pilot_inputs.py `
  --source-audit runs/dataset-audit/stage0-combined-20260810-08/record-audit.jsonl `
  --split-simulations runs/dataset-audit/stage0-combined-20260810-08/split-simulations.jsonl `
  --selection configs/e2e-pilot/cyberseceval-v2-selection-v1.json `
  --output-dir data/e2e-pilot/cyberseceval-v2-cwe78-cwe89-v1
```

Run local validation before allocating server resources:

```powershell
python -m secaware.cli preflight --config configs/e2e-pilot/local-preflight-v3.yaml
```

The real server run uses
`configs/e2e-pilot/server-qwen25-coder-32b-bailian-v1.yaml`. The Bailian key and
the local OpenAI-compatible service key are read from environment variables;
credentials are never written to configuration, commands, logs, or artifacts.

## Known preparation errors

During selection inspection, two stale field assumptions were rejected before
any artifact was written: split assignments are keyed by `cluster_id`, not
`task_id`, and record identifiers are strings while the audited task cluster is
stored in `task_cluster_id`. The builder validates the actual schema so these
errors cannot silently recur. The first local validation attempt also used the
removed `prepare` command; the registered command is `preflight`, and the
reproduction command above records that current interface. The first stage run
then showed that transactional stages require an absolute run directory. The
relative-path `local-preflight-v1` failure is preserved, while
`local-preflight-v2` freezes the explicit worktree path used by this machine.
`local-preflight-v3` retains that path and validates the discover-only observed
generation isolation fix.
The first server deployment used recursive SCP and timed out after transferring
only part of 329 small files. That incomplete directory is preserved as
`e2e-pilot-20260814-01`; deployment `-02` uses one archive plus a separately
permissioned `.env` file.
