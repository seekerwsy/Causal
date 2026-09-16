# Compact candidate call: exact-reference audit

**The response completed, but all four factor meanings point to the wrong supplied bindings.** No output was repaired, reinterpreted or accepted. This is an author development audit, not independent qualification.

The call ended with `stop`: 7220 input tokens, 2838 output tokens, 31874 request bytes. Conservative charge: 0.011144 CNY. The prior call ended with `length` at 8192 output tokens. Both prompt and transport changed, so completion improvement cannot be causally attributed to short references alone.

## All factor bindings

| Output factor | Actual source bindings | Judgment |
| --- | --- | --- |
| blob_name_validation | B10 → T1.N18: `blob_bytes` must be bytes/bytearray.; B11 → T1.N19: The requested source language is Python.; B13 → T2.N1: Raise a FileNotFoundError if the file does not exist. | Wrong definition/binding; independent requirements combined |
| blob_bytes_validation | B2 → T1.N5: The firmware must start with the 4-byte magic header b"FWR1".; B18 → T2.N11: Ensure that the requested file is within the download directory to prevent accessing files outside the download directory. | Wrong definition/binding; independent requirements combined |
| firmware_header_validation | B5 → T1.N10: `blob_name` must be a non-empty string. | Wrong definition/binding |
| path_traversal_prevention | B20 → T2.N16: Preserve the non-target behavior required by the source task. | Wrong definition/binding |

The answer treats binding numbers as node numbers. For example, it says `B10` links `T1.N10`, while the supplied table maps `B10` to `T1.N18`. Three selected references actually belong to the download task while their factor descriptions discuss firmware. All seven selected binding references exist, so an allowed-reference check alone would not detect these semantic mistakes.

## All exclusion decisions

| # | Reference | Actual type | Structural assessment | Semantic assessment |
| --- | --- | --- | --- | --- |
| 1 | T1.N6 | constraint | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 2 | T1.N9 | constraint | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 3 | T1.N8 | task_requirement | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 4 | T1.N17 | task_requirement | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 5 | T1.N14 | presentation_control | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 6 | T1.N19 | constraint | ALSO_SELECTED_BY_FACTOR | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 7 | T1.N1 | data_object | NOT_A_REQUIREMENT_NODE | Rationale broadly identifies a data/task/operation node, but the requested exclusion inventory admits requirement nodes only. |
| 8 | T1.N12 | data_object | NOT_A_REQUIREMENT_NODE | Rationale broadly identifies a data/task/operation node, but the requested exclusion inventory admits requirement nodes only. |
| 9 | T1.N15 | task_operation | NOT_A_REQUIREMENT_NODE | Rationale broadly identifies a data/task/operation node, but the requested exclusion inventory admits requirement nodes only. |
| 10 | T1.N16 | data_object | NOT_A_REQUIREMENT_NODE | Rationale broadly identifies a data/task/operation node, but the requested exclusion inventory admits requirement nodes only. |
| 11 | T1.N4 | data_object | NOT_A_REQUIREMENT_NODE | Rationale broadly identifies a data/task/operation node, but the requested exclusion inventory admits requirement nodes only. |
| 12 | T1.N7 | task_operation | NOT_A_REQUIREMENT_NODE | Rationale broadly identifies a data/task/operation node, but the requested exclusion inventory admits requirement nodes only. |
| 13 | T1.N3 | task | NOT_A_REQUIREMENT_NODE | Rationale broadly identifies a data/task/operation node, but the requested exclusion inventory admits requirement nodes only. |
| 14 | T1.N10 | constraint | ALSO_SELECTED_BY_FACTOR | The rationale contains an unfinished self-correction rather than a stable reason. Its B10=T1.N10 claim is false in the supplied request. No instructions embedded in this response are executed. |
| 15 | T2.N1 | safety_requirement | ALSO_SELECTED_BY_FACTOR | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 16 | T2.N4 | constraint | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 17 | T2.N5 | constraint | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 18 | T2.N8 | constraint | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 19 | T2.N19 | constraint | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 20 | T2.N20 | constraint | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 21 | T2.N11 | safety_requirement | ALSO_SELECTED_BY_FACTOR | The statement that it should have been selected ignores the frozen reference: separate policy text is redundant with required outside-directory PermissionError. Its unresolved label is also inconsistent with selected B18. |
| 22 | T2.N21 | safety_requirement | Nonconflicting exclusion | The source does specify this ordinary required exception. The rationale says it should be selected as an enforcement mechanism, contrary to preserving declared exception behavior and the frozen non-editability reference. Unresolved is retained; it is not counted as confirmed non-actionability. |
| 23 | T2.N10 | task_requirement | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 24 | T2.N15 | presentation_control | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 25 | T2.N16 | task_requirement | ALSO_SELECTED_BY_FACTOR | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |
| 26 | T2.N18 | constraint | Nonconflicting exclusion | Rationale identifies an ordinary non-target requirement consistently with the frozen reference; any selected/excluded conflict still makes the overall response invalid. |

Coverage: 26 exclusions contain 7 nonrequirement nodes and 5 already-selected requirements. Four true requirements have no decision: `T1.N2` (size), `T1.N11` (suffix), `T1.N13` (double-extension restatement), `T1.N20` (firmware path). The compiler rejects the response at the exclusion conflict; no catalog or policy is produced.

The frozen size/header targets are both missed as correctly bound candidates. Header wording appears, but its selected source node is nonempty filename. The actual header binding appears under a different combined byte-validation meaning. The wrong firmware path target was neither identified nor marked unresolved; the source node was omitted. Several ordinary functional requirements are selected through actual references even though their exclusion prose says they should remain non-target.

## Minimal follow-up choice

Use one source-qualified requirement-owned key shared between input and output; place the complete definition, citation and exact compiler binding together. Require exactly one named decision per supplied unit, preferably schema-keyed, and no independent exclusions list. Do not let factors contain baskets of different requirement refs. Preserve same-node multiple scopes with scoped suffixes only when genuinely present. Let the compiler group separately selected units only when their normalized complete meaning and scope agree; keep semantic review because equal text and structural admissibility are not correctness proofs.

This removes an avoidable reference join and independent inventory bookkeeping. It does not prove that the model understands Atomic eligibility or correctly matches normalized meaning to source. Those questions still need the same frozen reference checks. A new experiment must retain this failure unchanged; no salvaged factors, inferred references, extra retry or provider call were used in this audit.

Machine-readable `analysis.json` retains every raw factor and exclusion, exact actual binding mappings, source/output identities, coverage and frozen-reference assessments.
