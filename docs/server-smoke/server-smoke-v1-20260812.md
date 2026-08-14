# Server smoke v1 deployment and execution record

## Frozen scope

- Remote host: `121.48.163.133:9086`, account `wsy`.
- Deployment: `/home/wsy/secaware-deployments/server-smoke-20260812-01`.
- Python environment: `/home/wsy/secaware-environments/server-smoke-py312-20260812-01`.
- Execution record: `/home/wsy/secaware-experiments/executions/server-smoke-v1-20260812-01`.
- Pipeline run: `/home/wsy/secaware-experiments/runs/server-smoke-v1-20260812-01`.
- Generator: existing local Ollama OpenAI-compatible service, model `qwen3:32b`, one seed.
- Functional evaluator: Ali Bailian `qwen3.5-flash-2026-02-23`, two blind passes.
- Input: four security-neutral Python discover prompts covering CWE-22, CWE-89, and CWE-78.
- This run validates provider/runtime compatibility. It is not a discovery or confirmation result.

## Execution order

1. Build a source/data snapshot that excludes Git metadata, local virtual environments, caches,
   and all historical `runs` artifacts.
2. Transfer `.env` separately, set mode `0600`, and keep it outside all manifests and archives.
3. Verify local and remote snapshot digests before extracting into a new deployment directory.
4. Create the fixed Python 3.12 environment and install the declared project extras.
5. Run the targeted server test gate.
6. Run production preflight.
7. Run the two-case Bailian canary.
8. Run four sequential observed-generation requests through the existing Ollama service.
9. Run the locked Semgrep/Bandit observed Oracle once over the four generated programs.
10. Inspect request, attempt, code, Oracle, provenance, timing, failure, and resource artifacts before any
   expansion.

## Error ledger

1. The first remote directory/service probe embedded Bash loop variables in a PowerShell command.
   PowerShell expanded them before SSH, so the remote loop produced syntax errors. No remote state
   changed. The audit was rerun with literal, loop-free paths and ports.
2. The first local `bash -n` attempt passed a Windows backslash path to WSL; the path collapsed to
   `scriptsrun_server_smoke_v1.sh`, so the script was not checked. This is not counted as a pass.
   Both server scripts must pass native remote `bash -n` before environment creation or execution.
3. The first snapshot command used an invalid PowerShell-to-native array expansion for Windows
   `tar`, which produced an incomplete local archive attempt and exited nonzero. Nothing was
   uploaded. The failed deployment record is retained; the replacement snapshot uses a frozen
   top-level input list file and a new immutable record directory.
4. The replacement `tar -T` snapshot also failed locally before upload because Windows `tar`
   interpreted entries from the PowerShell-generated list as empty directory arguments. The failed
   `-02` record is retained. The `-03` snapshot passes the audited top-level paths as explicit
   native arguments and applies the same exclusion and archive-content gates.
5. The explicit-path snapshot exposed the exact cause: `manifests`, `snapshots`, and `sources` were
   listed from the main-workspace inventory but do not exist in this worktree, matching the three
   failed directory visits. The `-04` snapshot uses only the 15 paths verified present immediately
   before archiving. No prior snapshot was uploaded.
6. The `-04` archive and separate `.env` reached the new mode-`0700` transfer directory, but the
   first remote `sha256sum -c` rejected the Windows CRLF checksum line and stopped before
   extraction. The deployment directory was not created. The original checksum file is retained;
   an LF-only checksum is added and must pass before extraction. The `.env` value is never printed.
7. The first post-install inspection command was rejected locally by PowerShell because an embedded
   Python `+` expression was parsed before SSH. No remote command ran. The inspection was repeated
   with `pip show` and simple shell commands; Python 3.12.13, all locked package versions, 73 passing
   targeted tests, idle GPUs, Ollama reachability, and Bailian endpoint reachability were confirmed.
8. The first failed-run inspection reused remote shell variables inside a PowerShell SSH string;
   PowerShell expanded them locally, so `cat` received a heading as an option. No experiment file
   changed. Failure inspection is repeated with literal remote paths and no shell variables.
9. Execution `server-smoke-v1-20260812-01` passed preflight and all four blind Bailian canary calls,
   then failed closed on its first Ollama response. Preserved raw-response diagnostics show
   `finish_reason=length`, empty final content, and exactly 1024 completion tokens. The same frozen
   request with `reasoning_effort=none` returned `finish_reason=stop` and non-empty content. This is
   treated as a deterministic thinking-budget compatibility defect, not model randomness and not a
   reason to weaken the provider response contract.
10. The first standalone version-2 preflight gate did not source the protected deployment `.env`,
    so it stopped with `provider authentication is unavailable` before any provider call or run
    creation. The version-2 configuration and script digest checks had already passed. The gate is
    repeated with the same environment-loading step used by the formal runner; the failed command is
    retained as an operational error rather than attributed to the model or configuration.
11. Version-2 execution generated and sealed all four programs with four one-attempt provider
    successes, then the Oracle stage stopped with `analyzer executable is unavailable`. The runner
    invoked the fixed environment's Python by absolute path but did not prepend that environment's
    `bin` directory to `PATH`; therefore analyzer child-process lookup could not find the installed
    Semgrep and Bandit executables. A separate versioned recovery execution adds only the missing
    environment path, verifies analyzer paths and versions, authenticates the three sealed generation
    ledgers before and after recovery, and fills the previously absent Oracle artifact without
    repeating generation or overwriting either failed execution record.
12. The first external recovery gate embedded remote `$PATH` in a PowerShell double-quoted SSH
    command. PowerShell expanded the variable locally and produced an invalid remote `export`; the
    recovery script's preceding `bash -n` check passed, but no recovery execution started. The gate
    is repeated with explicit server paths and no cross-shell variable interpolation.
13. The first Oracle recovery found the analyzer commands but failed before producing output. Exact
    diagnostics established that SecAware's Linux user/PID/mount/private-proc and sealed-memfd
    runtime probe passes, while the fixed Python console scripts have two launcher compatibility
    issues: Semgrep 1.168.0 invokes `uname` but the analyzer-minimal `PATH` contains only the entry
    script directory; Bandit 1.9.4 derives its version prefix from the sealed `/proc/self/fd/N`
    script path. The second recovery freezes auditable Semgrep/Bandit entry wrappers that restore
    only `sys.argv[0]`, plus a byte-for-byte copy of `/usr/bin/uname`, in one compatibility directory.
    SecAware still seals the wrapper and interpreter, applies all namespaces, verifies the exact
    tool versions, and records hashes for both wrappers and `uname`. A locked two-sample real-tool
    regression must pass through this directory before the four generated programs are evaluated.
14. The first compatibility-directory real-tool regression reached both tools successfully, but the
    Oracle preflight rejected Bandit's second version line: Conda Python inserts distribution build
    metadata between the Python version and build tuple, outside the frozen parser grammar. No model
    output was evaluated. The next immutable compatibility directory changes only the Bandit
    `--version` branch: it reads the installed `bandit` distribution version and emits a canonical
    Python implementation/compiler line; every scanning invocation still calls Bandit 1.9.4's
    original `main`. The locked real-tool regression is repeated before recovery.
15. The revised compatibility-directory real-tool regression passed all six tests, including the
    locked secure/insecure corpus classification. Its first recovery script invocation then stopped
    before Oracle preflight because the script itself tried to resolve `cat` after restricting
    `PATH` to the compatibility directory. No analyzer or model-output evaluation started. The next
    immutable input uses `/usr/bin/cat` for its own ledger write while preserving the same restricted
    analyzer `PATH`, wrapper bytes, `uname` bytes, generated-code hashes, and Oracle policy.
16. The new source snapshot uploaded successfully, but PowerShell's ASCII writer still terminated
    the checksum line with CRLF. Remote `sha256sum -c` therefore treated the carriage return as part
    of the archive filename and stopped before deployment extraction. The uploaded archive and
    protected `.env` remain unchanged; the original checksum is retained and an LF-only remote copy
    is created for the gate, matching the previously documented cross-platform checksum failure.
17. The final immutable deployment uses snapshot SHA-256
    `d512559144e63b19874b9d44023f188604021ad373551f6aea345374c4447e26`, a newly cloned and
    rebound Python 3.12.13 environment, and a new `server-smoke-v1-20260812-03` run. The environment
    gate passed 151 tests; the production Oracle compatibility gate passed all six real-tool tests.
    The four-task smoke then completed with four one-attempt generations, four syntax-valid decoded
    Python programs, four evaluable Oracle records, three `secure` labels, and one `insecure` label.
    The insecure command-version task has two independent Bandit findings (B404 and B603, CWE-78),
    consistent with its generated `subprocess.run` over a mapping-provided executable. This outcome
    is a smoke/runtime validation only and is not a causal or model-quality estimate.

## Final artifact locations

- Remote deployment: `/home/wsy/secaware-deployments/server-smoke-20260812-02`.
- Remote fixed environment: `/home/wsy/secaware-environments/server-smoke-py312-20260812-02`.
- Remote frozen execution inputs:
  `/home/wsy/secaware-experiments/inputs/server-smoke-v1-20260812-07-final`.
- Remote execution record:
  `/home/wsy/secaware-experiments/executions/server-smoke-v1-20260812-03`.
- Remote run artifacts: `/home/wsy/secaware-experiments/runs/server-smoke-v1-20260812-03`.
- Local snapshot and downloaded core results:
  `runs/deployment/server-smoke-20260812-05`.

## Version 2 corrective execution

- Reuse the immutable code deployment, fixed Python environment, protected `.env`, four prompts,
  model, seed, token budget, Oracle policy, and Bailian canary settings from version 1.
- Freeze a new configuration and runner under
  `/home/wsy/secaware-experiments/inputs/server-smoke-v1-20260812-02`.
- The only generation-request change is `reasoning_effort=none`, which disables Qwen3's default
  thinking so the 1024-token budget is available for final code.
- Write execution records to
  `/home/wsy/secaware-experiments/executions/server-smoke-v1-20260812-02` and pipeline artifacts to
  `/home/wsy/secaware-experiments/runs/server-smoke-v1-20260812-02`; never modify version 1.
