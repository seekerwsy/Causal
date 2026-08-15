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

## First approved live result

`runs/e2e-pilot/gate-b-placebo-repair-v1-live-20260815-01` made exactly the two
approved provider calls and received two structurally valid responses without retries or transport
errors. Both responses preserved the source prefix, were non-empty, differed from no-op, and used
natural presentation-only practice wording. They failed only the frozen length boundary: the
57-character target received a 43-character placebo suffix, and the 55-character target received a
47-character suffix. No extractor or code-generation call was made.

The failure is retained and is not reclassified or repaired in place. Range guidance alone was
insufficient for this executor.

## Reviewed-clause v2 preflight

The v2 repair freezes one reviewed presentation-only suffix for both tasks:

```text
 Keep the requested code concise and clearly organized.
```

The leading space is part of the suffix, giving exactly 55 Unicode characters. It lies inside both
registered ranges and changes only response presentation. The v2 system and request contracts require
the executor to copy this exact suffix after the unchanged source; shortening or paraphrasing is a
hard failure.

`runs/e2e-pilot/gate-b-placebo-repair-v2-plan-20260815-01` froze two new requests with
zero provider attempts. The reviewed-clause digest, request policy, system-template policy, target
and no-op dependencies, and two-call budget are all distinct from v1. A v2 live run requires separate
authorization and remains one attempt per placebo with no semantic retry.

## Approved v2 live result

`runs/e2e-pilot/gate-b-placebo-repair-v2-live-20260815-01` made exactly the two
separately approved provider calls. Both responses copied the reviewed suffix exactly, preserved the
source Prompt byte-for-byte as a prefix, differed from no-op, and measured 55 Unicode characters.
The two records therefore passed their registered 51--63 and 49--61 ranges. There were two responses,
two validation artifacts, zero failures, zero transport errors, and zero retries. No extractor or
code-generation call was made.

This result repairs only the intervention-protocol validity of the two placebo texts. Task- and
safety-feature invariance is still decided by the separately planned blind extractor revalidation.
