# Compact candidate development check

One new bounded Qwen Flash request reuses the two previously exposed, frozen natural source graphs. It compares completion and selection behavior against the retained truncated response. Both transport and prompt changed, so this is not a pure causal attribution test and cannot establish extraction quality or stability.

- `proposal-request`: full canonical source request plus exact compact model request; no evaluation references sent.
- `proposal-config`: same model/seed/temperature, thinking disabled, 8192 output tokens, one call, no retry; reserve at most 0.25 CNY, including failed or unknown usage.
- `evaluation`: pre-output checks and unchanged prior source references/audit. These are author development judgments, not independent qualification.
- `execution`: file-level identity of the frozen working-tree source snapshot.
- `execution-source.tar.gz`: exact source and inputs; `launch.sh` verifies it and executes inside the existing Docker environment.
- `propose.py`: copied thin existing runner with only the config-directory name changed; retains exact wire request/response and conservative charge. It neither updates the spending ledger nor accepts candidates without semantic review.

Expected remote output: `/home/wsy/work/prompt-mechanism-study/results/tsg-reliable-construction-v1/compact-candidate/run/{call,compiled,summary}`. Retrieval archive: input package `results.tar.gz`.

Offline replay after retrieval uses the frozen source snapshot and the same runner with a third argument pointing to the retained `run` directory. The HTTP request must match byte for byte; a fake replay credential is used and no network call is made.

Preparation made zero provider calls. No paper changes, source correction, generated code or formal experiment is authorized by this diagnostic. Root settles actual conservative cost once after execution.
