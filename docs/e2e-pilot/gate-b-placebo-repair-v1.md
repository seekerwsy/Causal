# Gate B Placebo Repair v1

## Frozen contract

This bounded repair replaces only the two invalid `length_matched_placebo` intervention texts from
the preserved failed Gate B attempt. The target, no-op, generic-reminder, source, Gate A assignment,
and AllowedDelta artifacts remain immutable.

Suffix length is measured in Unicode characters. For target suffix length `L`, an admitted placebo
must satisfy:

```text
abs(placebo_length - L) <= max(5, ceil(0.10 * L))
```

It must also be non-empty, differ from the corresponding no-op suffix, and preserve the source
Prompt byte-for-byte as its prefix. The two frozen target lengths are 57 and 55 characters, producing
admissible placebo ranges of 51--63 and 49--61 characters.

This is a pre-code-generation intervention-protocol gate. It is not an outcome filter, security
Oracle, extractor decision threshold, or post-randomization ITT exclusion. Task and safety feature
invariance remains subject to the independent blind extractor in the subsequent complete Gate B
revalidation.

## Execution boundary

The repair LLM receives the source Prompt as inert data, the placebo AllowedDelta, and only the
numeric length contract. It does not receive the target suffix text, generated code, Oracle output,
experiment outcome, or expected security label. The system contract requires one natural,
presentation-only appended sentence and forbids security or target-mechanism language.

Exactly two provider calls are allowed, one per invalid placebo. Temperature is zero, each request
has one attempt, and no semantic retry is allowed. All request, response, validation, configuration,
environment, policy, and provenance artifacts are written to a new run directory.

## Zero-provider preflight

`runs/e2e-pilot/gate-b-placebo-repair-v1-plan-20260815-01` completed with zero provider
attempts. It froze exactly two distinct `length_matched_placebo` requests, recovered target lengths
57 and 55 from the preserved intervention pairs, and embedded the corresponding 51--63 and 49--61
admission ranges. The ten boundary tests for accepted endpoints, rejected out-of-range lengths,
empty/no-op collisions, and invalid input types all passed.
