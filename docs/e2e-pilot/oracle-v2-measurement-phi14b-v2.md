# Oracle v2 Phi-4 14B measurement canary

This model-specific canary reuses the two accepted Oracle-v2 measurement tasks, the final blind
Gate B variants, functional contracts, four arm roles, and confirmation seed set from the Qwen 7B
canary. Model ID is the only producer-stratum change. Effects are not pooled across models, and this
two-task run remains an engineering measurement gate rather than a causal-effect estimate.

The zero-provider Gate A run is retained at
`runs/e2e-pilot/randomized-exploratory-discovery-phi14b-v2-20260818-01`. It passed with two tasks,
two blocks, eight assignments, eight variants, zero errors, and zero pending records. Deterministic
target recognition was 0/2 and remains diagnostic only; Gate B supplies the accepted blind semantic
validation and is not rerun for a generator-only change.

One preparation check incorrectly asserted that the validated Pydantic model list was a tuple. The
check failed before any provider call; the subsequent Gate A command was independent and passed.
The corrected check compares the actual model value and records this type-assumption error here so
it is not repeated.

The first server Gate C planning attempt was rejected before any model call because the new Git
archive materialized the selection and Prompt inputs with LF, while the accepted Gate B artifacts
were built from the prior deployment's CRLF bytes. The semantic records were unchanged, but their
content hashes and derived exploratory variant IDs differed. The failed `-01` Gate A and Gate C plan
directories remain intact. The replacement `-02` Gate A reads the exact authenticated input bytes
from the Qwen measurement deployment, records their hashes, and uses the Phi model ID only for its
randomization coordinate. Future main-experiment inputs must be normalized and pinned to LF before
Gate A/B freeze rather than repaired after either gate.
