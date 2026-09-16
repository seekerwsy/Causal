# Requirement-keyed compact candidate development check

This is a new one-call check after the immutable V1 response failed reference grounding. The same two retained natural source graphs and prior semantic references are used. No source correction, protected task, generated code or formal evidence is added.

The only active proposer interface now uses exactly one schema-required decision for each original requirement node reference. Definition, citation and all complete bindings are colocated on that node. There is no second B-number namespace, separate exclusions inventory or model-selected basket of nodes/scopes. The compiler restores all bindings and applies existing same-meaning/scope grouping; explicit semantic review remains required.

Inputs/outputs:
- `proposal-request`: canonical original request, compact node-bound model request, prompt and exact per-request response schema.
- `proposal-config`: Qwen Flash, thinking off, same seed/model/8192 output limit; exactly one call, <=0.25 CNY conservative debit, no retry.
- `evaluation`: original reference/audit unchanged, initial truncation baseline and V1 exact-reference failure metrics. No evaluation references are sent to the model.
- `execution`: exact source file identities; `execution-source.tar.gz` is the self-contained frozen source/input package.
- `propose.py`: the existing thin one-call recorder/replayer; no ledger settlement or automatic semantic acceptance.
- `launch.sh`: verifies archive and environment, refuses existing output, then writes `/home/wsy/work/prompt-mechanism-study/results/tsg-reliable-construction-v1/compact-candidate-v2/run/{call,compiled,summary}` and packages results at the matching input root.

Transport and prompt changed together. This is not a pure causal ablation or a demonstration of stable semantic quality. Frozen size/header coverage and false inclusions are checked separately from schema completion. V1 remains untouched and its exact old implementation is available in its original execution archive; no second provider transport remains active.

Preparation made zero provider calls. Root reviews before launch and settles actual conservative cost once. Offline shape checks and candidate tests do not count as experimental results. After retrieval, replay with the frozen source and a third runner argument pointing to the retained run directory; exact HTTP bytes are checked without network use.
