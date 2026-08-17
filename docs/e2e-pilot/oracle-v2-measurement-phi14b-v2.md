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

Because Gate B is generator-independent, the cross-model planner uses an explicit bounded mapping
policy for this canary. Each Phi Gate A assignment must match exactly one accepted Gate B record on
task ID, arm role, and target feature. It then rechecks the Gate B validation status, Prompt hash,
intervention provenance, graph record, and source task. The default planner policy remains exact
variant-ID matching; semantic coordinate matching is enabled only in the Phi v2 configuration.

The first two server plans are preserved as zero-call failures. `-01` exposed the exact-ID coupling;
`-02` confirmed that a later repository deployment did not contain the historical CRLF source
bytes. After the explicit cross-model mapping implementation passed its targeted tests, the `-03`
plan completed with two blocks, eight assignments, eight generation requests, two functional
contracts, two profile-scoped Oracle decisions, zero errors, and zero provider calls. The frozen
pilot is the CWE-89 target assignment
`assignment_af16c8bb735515892d83122453c4272eaedc6529c499431b85b3275392eb6d70`.

The first live preflight rejected a manually transcribed pilot ID containing one extra `5`; no
provider call was possible. The surrounding shell also started the already prepared model service
without conditioning that step on the preflight exit code. The service reached `READY`, but no
experimental request was issued. The corrected configuration copies the assignment ID directly from
the authenticated plan, and subsequent execution gates the pilot on a successful new preflight.

The corrected preflight validated all eight units with zero provider calls. Its conditionally gated
CWE-89 target pilot then completed one generation, one single-pass functional judgment, and one
profile-scoped Oracle decision. Functionality passed; Oracle parsed the program, identified one SQL
execution sink with constant query text, and returned an evaluable secure label. The exact model
request and pre-normalization response are closed by the unit manifest. This authorizes only the
seven pending 14B canary assignments and remains outside any causal-effect claim.
