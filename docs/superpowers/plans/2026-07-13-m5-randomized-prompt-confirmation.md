# M5 Randomized Prompt Confirmation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Materialize typed ADD/REMOVE targets, build and independently validate family-specific prompt arms, freeze complete protocols, randomize held-out task blocks, and execute assignment-bound generation plus Oracle evaluation.

**Architecture:** Semantic `TargetSpecRecord` and `ConfirmationProtocolRecord` definitions are shared across held-out tasks and form the ITT/JCI grouping keys. Task-specific `TargetInstanceRecord` and `ConfirmationProtocolInstanceRecord` bind source/counterpart prompts for freezing and randomization. `AllowedDeltaRecord` states the only graph changes each arm may make. Variants are built by one locked executor, independently re-extracted by the M4A backend, frozen before deterministic task-level block assignment, and then passed to generation through assignment-bound request records.

**Tech Stack:** Python 3.10+, Pydantic 2, NetworkX 3, shared locked structured-LLM transport, deterministic SHA-256 RNG, existing generation/Oracle transactions, Typer, pytest, Ruff.

---

## File responsibility map

- `src/secaware/schema/experiments.py`: target, protocol, delta, variant, assignment, and execution records.
- `src/secaware/schema/records.py`: prompt role and counterpart coordinates.
- `src/secaware/intervention/arm_catalog.py`: finite family/operation arm templates.
- `src/secaware/intervention/targeting.py`: frozen hypothesis to semantic definitions, then source
  prompts to task-specific target/protocol instances.
- `src/secaware/intervention/attestation.py`: exact prompt-role/counterpart attestations.
- `src/secaware/intervention/executors.py`: deterministic and LLM text execution.
- `src/secaware/intervention/graph_patch.py`: typed graph-native intended patches.
- `src/secaware/intervention/variant_validation.py`: independent extraction, `AllowedDelta`, neutrality, and diagnostics.
- `src/secaware/experiments/randomization.py`: complete block construction and assignment.
- `src/secaware/generation/request_planner.py`: assignment-bound confirmation requests.
- `src/secaware/generation/openai_compatible_provider.py`: generated versus valid terminal outcome.
- `src/secaware/pipeline/stages/prompt_variants.py`: complete pre-randomization freeze transaction.
- `src/secaware/pipeline/stages/randomization.py`: immutable assignment manifest transaction.
- `src/secaware/pipeline/stages/confirmation_generation.py`: exact assignment execution coverage.
- `src/secaware/cli.py`: thin build/randomize/generate/Oracle command registration.

### Task 1: Add experiment schemas and the finite family/operation arm catalog

**Files:**
- Create: `src/secaware/schema/experiments.py`
- Modify: `src/secaware/schema/__init__.py`
- Create: `src/secaware/intervention/arm_catalog.py`
- Modify: `src/secaware/intervention/__init__.py`
- Create: `tests/test_experiment_schema.py`
- Create: `tests/test_arm_protocol_catalog.py`

- [ ] **Step 1: Write failing schema/catalog tests**

```python
def test_safety_add_has_exact_four_arm_roles() -> None:
    hypothesis = _safety_hypothesis()
    protocol = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", "add", hypothesis=hypothesis),
    )
    assert protocol.arm_roles == (
        ArmRole.TARGET_PATCH,
        ArmRole.NOOP_REWRITE,
        ArmRole.LENGTH_MATCHED_PLACEBO,
        ArmRole.GENERIC_SECURITY_REMINDER,
    )
    assert protocol.hypothesis_outcome_variable_id == "y.secure_functional"
    assert "safety_add.target_minus_noop.y_secure_functional" in protocol.preregistered_contrast_ids
    matched = next(
        item
        for item in protocol.contrasts
        if item.arm_contrast_id == "safety_add.target_minus_noop"
        and item.outcome_id == protocol.hypothesis_outcome_estimand_id
    )
    assert matched.source_outcome_variable_id == protocol.hypothesis_outcome_variable_id
    assert matched.expected_sign == protocol.expected_hypothesis_contrast_sign


def test_safety_remove_has_distinct_protocol_and_allowed_delta() -> None:
    hypothesis = _safety_hypothesis()
    add = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", "add", hypothesis=hypothesis),
    )
    remove = materialize_arm_protocol(
        hypothesis,
        _target("safety.path_normalization", "remove", hypothesis=hypothesis),
    )
    assert add.arm_protocol_id != remove.arm_protocol_id
    generic = _arm(remove, ArmRole.GENERIC_SECURITY_REPLACEMENT)
    assert {item.feature_id for item in generic.allowed_delta.allowed_transitions} == {
        "safety.path_normalization",
        "safety.generic_security_reminder",
    }
```

Add strict tests for all role enums, family/operation mismatch, duplicate arms, target feature outside
the catalog, unsupported operation, target/no-op protocol omission, target feature appearing in a
placebo delta, generic-security role in task/presentation protocols, presentation safety changes,
task safety changes, four-arm task protocol without a functional contract, arbitrary runtime arm
registration, ID/digest mutation, tuple order, and safe repr/error surfaces.
Mutate treatment/control, outcome, priority, expected sign, multiplicity family, and contrast order one
at a time and require both `contrast_set_sha256` and `arm_protocol_id` revalidation to fail closed.
Also reject a frozen-hypothesis digest mismatch, outcome/estimand drift, or a hypothesis-contrast sign that differs
from the selected operation's `ExpectedOperationContrast`.

- [ ] **Step 2: Run schema/catalog tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_experiment_schema.py tests/test_arm_protocol_catalog.py
```

Expected: FAIL because experiment records and arm catalog do not exist.

- [ ] **Step 3: Implement exact experiment enums and immutable records**

```python
class PromptRole(str, Enum):
    NEUTRAL_BASELINE = "neutral_baseline"
    POSITIVE_SAFETY_CONTROL = "positive_safety_control"
    TASK_FUNCTION_BASELINE = "task_function_baseline"
    TASK_FUNCTION_VARIANT = "task_function_variant"
    PRESENTATION_BASELINE = "presentation_baseline"
    PRESENTATION_VARIANT = "presentation_variant"


class InterventionMode(str, Enum):
    TEXT_NATIVE = "text_native"
    GRAPH_NATIVE = "graph_native"


class InterventionExecutorKind(str, Enum):
    DETERMINISTIC = "deterministic"
    LLM = "llm"


class ArmRole(str, Enum):
    TARGET_PATCH = "target_patch"
    NOOP_REWRITE = "noop_rewrite"
    LENGTH_MATCHED_PLACEBO = "length_matched_placebo"
    GENERIC_SECURITY_REMINDER = "generic_security_reminder"
    TARGET_REMOVE = "target_remove"
    NOOP_RETAIN = "noop_retain"
    LENGTH_MATCHED_SHAM_EDIT = "length_matched_sham_edit"
    GENERIC_SECURITY_REPLACEMENT = "generic_security_replacement"
    TASK_TARGET = "task_target"
    TASK_NOOP = "task_noop"
    TASK_LENGTH_PLACEBO = "task_length_placebo"
    TASK_GENERIC_CONTROL = "task_generic_control"
    PRESENTATION_TARGET = "presentation_target"
    PRESENTATION_NOOP = "presentation_noop"
    PRESENTATION_MATCHED_CONTROL = "presentation_matched_control"
```

Persist these core records:

```python
class TargetSpecRecord(VersionedModel):
    schema_version: Literal["1.0"]
    target_spec_id: str = Field(pattern=r"^target_[0-9a-f]{64}$")
    hypothesis_id: str = Field(pattern=r"^hypothesis_[0-9a-f]{64}$")
    frozen_hypothesis_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    feature_family: FeatureFamily
    feature_id: str
    operation: FeatureOperation
    hypothesis_outcome_variable_id: str
    hypothesis_outcome_estimand_id: str
    expected_hypothesis_contrast_sign: Literal["positive", "negative", "null", "two_sided"]


class TargetInstanceRecord(VersionedModel):
    schema_version: Literal["1.0"]
    target_instance_id: str = Field(pattern=r"^target_instance_[0-9a-f]{64}$")
    target_spec_id: str = Field(pattern=r"^target_[0-9a-f]{64}$")
    task_id: str
    source_prompt_id: str
    source_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    counterpart_prompt_id: str | None
    counterpart_prompt_sha256: str | None
    source_prompt_role: PromptRole
    counterpart_required: bool


class FeatureTransition(StrictModel):
    feature_id: str
    from_states: tuple[FeatureState, ...]
    to_states: tuple[FeatureState, ...]


class AllowedDeltaRecord(StrictModel):
    allowed_transitions: tuple[FeatureTransition, ...]
    fixed_families: tuple[FeatureFamily, ...]
    fixed_feature_ids: tuple[str, ...]


class ArmSpecRecord(StrictModel):
    role: ArmRole
    allowed_delta: AllowedDeltaRecord


class PreRegisteredContrastSpec(StrictModel):
    contrast_id: str
    arm_contrast_id: str
    treatment_arm: ArmRole
    control_arm: ArmRole
    source_outcome_variable_id: str
    outcome_id: str
    priority: Literal["primary", "secondary", "diagnostic"]
    expected_sign: Literal["positive", "negative", "null", "two_sided"]
    multiplicity_family_id: str


class ConfirmationProtocolRecord(VersionedModel):
    schema_version: Literal["1.0"]
    arm_protocol_id: str = Field(pattern=r"^arm_protocol_[0-9a-f]{64}$")
    hypothesis_id: str = Field(pattern=r"^hypothesis_[0-9a-f]{64}$")
    frozen_hypothesis_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_spec_id: str = Field(pattern=r"^target_[0-9a-f]{64}$")
    feature_family: FeatureFamily
    operation: FeatureOperation
    arms: tuple[ArmSpecRecord, ...]
    hypothesis_outcome_variable_id: str
    hypothesis_outcome_estimand_id: str
    expected_hypothesis_contrast_sign: Literal["positive", "negative", "null", "two_sided"]
    contrasts: tuple[PreRegisteredContrastSpec, ...]
    contrast_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    functional_outcome_contract_id: str | None = None

    @property
    def arm_roles(self) -> tuple[ArmRole, ...]:
        return tuple(arm.role for arm in self.arms)

    @property
    def preregistered_contrast_ids(self) -> tuple[str, ...]:
        return tuple(item.contrast_id for item in self.contrasts)


class ConfirmationProtocolInstanceRecord(VersionedModel):
    schema_version: Literal["1.0"]
    protocol_instance_id: str = Field(pattern=r"^protocol_instance_[0-9a-f]{64}$")
    arm_protocol_id: str = Field(pattern=r"^arm_protocol_[0-9a-f]{64}$")
    target_instance_id: str = Field(pattern=r"^target_instance_[0-9a-f]{64}$")
    task_id: str
    source_prompt_id: str
    source_prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    counterpart_prompt_id: str | None
    counterpart_prompt_sha256: str | None


class FunctionalOutcomeContractRecord(VersionedModel):
    schema_version: Literal["1.0"]
    contract_id: str = Field(pattern=r"^functional_contract_[0-9a-f]{64}$")
    task_feature_id: str
    outcome_id: str
    expected_add_sign: Literal["positive", "negative", "two_sided"]
    expected_remove_sign: Literal["positive", "negative", "two_sided"]
    generic_control_feature_id: str | None
    evaluator_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
```

`AllowedDeltaRecord` is an upper bound: it rejects undeclared changes but never requires a permitted
transition to occur.

- [ ] **Step 4: Implement the finite arm materializer**

Use exhaustive `(FeatureFamily, FeatureOperation)` dispatch. Materialize target feature IDs into
the allowed transition while control feature IDs remain catalog-owned constants. Exact protocols:

```text
SAFETY ADD:
  TARGET_PATCH, NOOP_REWRITE, LENGTH_MATCHED_PLACEBO, GENERIC_SECURITY_REMINDER
SAFETY REMOVE:
  TARGET_REMOVE, NOOP_RETAIN, LENGTH_MATCHED_SHAM_EDIT, GENERIC_SECURITY_REPLACEMENT
TASK ADD/REMOVE:
  TASK_TARGET, TASK_NOOP, TASK_LENGTH_PLACEBO
  plus TASK_GENERIC_CONTROL only with a reviewed functional contract
PRESENTATION ADD/REMOVE:
  PRESENTATION_TARGET, PRESENTATION_NOOP
  plus PRESENTATION_MATCHED_CONTROL only when the target catalog entry declares it
```

Hard fixed-family rules match the approved specification. `TargetSpecRecord` and
`ConfirmationProtocolRecord` are semantic, cross-task definitions; their IDs must be identical for
every held-out task instance of the same frozen hypothesis/operation. `TargetInstanceRecord` and
`ConfirmationProtocolInstanceRecord` carry prompt/counterpart coordinates and are never ITT/JCI
grouping keys. The protocol ID covers the frozen hypothesis digest, semantic TargetSpec, ordered arm
definitions, outcome/estimand, contrast IDs, and optional functional
contract; it also covers every complete contrast field and `contrast_set_sha256`, not only the IDs.
The public materializer signature is
`materialize_arm_protocol(hypothesis, target, functional_contract=None)`: it first revalidates
`hypothesis_sha256`, requires target hypothesis/feature/family/operation/outcome/estimand coordinates to
match the frozen record, and requires the target-minus-no-op spec for the hypothesis estimand to equal
that operation's frozen `ExpectedOperationContrast`. That hypothesis-specific spec may be primary,
secondary, or diagnostic; it does not redefine the family-wide primary estimand. It adds
`TASK_GENERIC_CONTROL` only
when the supplied `FunctionalOutcomeContractRecord` names a reviewed generic task-control feature.
Do not expose registration or plugin hooks for arm roles.

The same finite materializer freezes complete estimands before variant construction. Safety protocols
expand each allowed arm contrast across this closed outcome set:

```text
y_secure_functional   primary
y_cwe_secure          secondary
y_cwe_insecure        secondary
y_cwe_unknown         diagnostic
y_oracle_evaluable    diagnostic
y_parse_ok             diagnostic
y_functional_ok        diagnostic
```

Use IDs `<arm_contrast_id>.<outcome_id>`. Safety ADD arm contrasts are target-minus-no-op,
target-minus-length-placebo, target-minus-generic, generic-minus-no-op, and placebo-minus-no-op;
Safety REMOVE uses the exact analogous target-remove/sham/generic contrasts. Freeze these exact safety
arm templates for `y_secure_functional`:

```text
ADD target_minus_noop       TARGET_PATCH - NOOP_REWRITE                    primary, positive
ADD target_minus_placebo    TARGET_PATCH - LENGTH_MATCHED_PLACEBO          secondary, positive
ADD target_minus_generic    TARGET_PATCH - GENERIC_SECURITY_REMINDER       secondary, two_sided
ADD generic_minus_noop      GENERIC_SECURITY_REMINDER - NOOP_REWRITE       diagnostic, two_sided
ADD placebo_minus_noop      LENGTH_MATCHED_PLACEBO - NOOP_REWRITE          diagnostic, null
REMOVE target_minus_noop    TARGET_REMOVE - NOOP_RETAIN                    primary, negative
REMOVE target_minus_sham    TARGET_REMOVE - LENGTH_MATCHED_SHAM_EDIT       secondary, negative
REMOVE target_minus_generic TARGET_REMOVE - GENERIC_SECURITY_REPLACEMENT   secondary, negative
REMOVE generic_minus_noop   GENERIC_SECURITY_REPLACEMENT - NOOP_RETAIN     diagnostic, two_sided
REMOVE sham_minus_noop      LENGTH_MATCHED_SHAM_EDIT - NOOP_RETAIN         diagnostic, null
```

Also freeze target-minus-no-op for `y_cwe_secure`, `y_cwe_insecure`, `y_cwe_unknown`,
`y_oracle_evaluable`, `y_parse_ok`, and `y_functional_ok`. CWE secure follows the primary sign, CWE
insecure reverses it, and unknown/evaluability/parse/functional diagnostics are two-sided. Thus each
safety protocol contains exactly eleven complete contrast specs. `y_secure_functional` remains the
safety experiment's global primary even when the discovery hypothesis ended at another registered Y;
the hypothesis-matched target-minus-no-op spec is validated independently at its predeclared priority.
Task protocols use their
reviewed functional-contract outcome as primary and only family-valid secondary outcomes;
presentation protocols use null/two-sided negative-control outcomes only. Contrast definitions are
unique by `(arm_protocol_id, contrast_id)` and their complete ordered canonical content contributes to
`arm_protocol_id`; M6 may validate and flatten them but cannot redefine them.

Derive `multiplicity_family_id` from the semantic TargetSpec ID, hypothesis digest, operation, and
versioned contrast-catalog ID;
never from `arm_protocol_id`, avoiding a digest cycle while still giving every target protocol a
separate pre-randomization family.

For task protocols, freeze target-minus-no-op (primary) and target-minus-length-placebo (secondary)
on the contract's `outcome_id`, using the contract's ADD/REMOVE sign. If the reviewed fourth arm is
present, also freeze target-minus-generic (secondary, two-sided) and generic-minus-no-op (diagnostic,
two-sided); always freeze placebo-minus-no-op (diagnostic, null). Freeze target-minus-no-op on the
safety/CWE outcomes as secondary or diagnostic two-sided checks. For presentation, freeze
target-minus-no-op for secure-functional and the three CWE indicators as negative-control contrasts
with expected sign `null`; if a matched presentation control exists, add target-minus-matched as
secondary `null` and matched-minus-no-op as diagnostic `null`. These are exhaustive materializer
rules, not runtime registration points.

- [ ] **Step 5: Re-run schema/catalog tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_experiment_schema.py tests/test_arm_protocol_catalog.py tests/test_prompt_feature_catalog.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/schema/experiments.py src/secaware/schema/__init__.py src/secaware/intervention/arm_catalog.py src/secaware/intervention/__init__.py tests/test_experiment_schema.py tests/test_arm_protocol_catalog.py
git commit -m "feat: add typed confirmation arm protocols"
```

### Task 2: Add prompt roles, counterpart provenance, and task-specific target/protocol instances

**Files:**
- Modify: `src/secaware/schema/records.py`
- Create: `src/secaware/intervention/attestation.py`
- Create: `src/secaware/intervention/targeting.py`
- Modify: `src/secaware/config.py`
- Create: `data/examples/prompt_attestations_demo.jsonl`
- Modify: `data/examples/prompts_demo.jsonl`
- Modify: `configs/demo.yaml`
- Modify: `configs/paper_v0.yaml`
- Create: `tests/test_prompt_role_attestations.py`
- Create: `tests/test_target_materialization.py`
- Modify: `tests/test_preflight.py`

- [ ] **Step 1: Write failing role/counterpart/target tests**

```python
def test_safety_remove_requires_exact_positive_to_neutral_counterpart() -> None:
    positive, neutral, attestations = _attested_path_pair()
    target = materialize_target_spec(_safety_hypothesis(), FeatureOperation.REMOVE)
    instance = materialize_target_instance(target, _safety_hypothesis(), positive, attestations)
    assert instance.source_prompt_role is PromptRole.POSITIVE_SAFETY_CONTROL
    assert instance.counterpart_required is True
    assert counterpart_for(instance, attestations).prompt_id == neutral.prompt_id


def test_two_tasks_share_semantic_ids_but_not_instance_ids() -> None:
    hypothesis = _safety_hypothesis()
    target = materialize_target_spec(hypothesis, FeatureOperation.ADD)
    protocol = materialize_arm_protocol(hypothesis, target)
    left = materialize_target_instance(target, hypothesis, _neutral_prompt(task_id="task-a"), _attestations())
    right = materialize_target_instance(target, hypothesis, _neutral_prompt(task_id="task-b"), _attestations())
    assert left.target_spec_id == right.target_spec_id == target.target_spec_id
    assert left.target_instance_id != right.target_instance_id
    assert materialize_protocol_instance(protocol, left).arm_protocol_id == protocol.arm_protocol_id
    assert materialize_protocol_instance(protocol, right).arm_protocol_id == protocol.arm_protocol_id


def test_forward_and_reverse_views_share_one_contrast_id() -> None:
    attestation = _attestation_for_exact_pair(owner=FeatureOperation.ADD)
    assert contrast_id(attestation, FeatureOperation.ADD) == contrast_id(
        attestation,
        FeatureOperation.REMOVE,
    )
    with pytest.raises(SecAwareError):
        materialize_non_owner_reverse_target(attestation)
```

Add rejection tests for missing/stale/duplicate attestation, prompt hash mismatch, cross-task
counterpart, different task/function text outside the variant clause, REMOVE without provenance,
ADD from a positive prompt, target outside frozen hypothesis operations, split not confirm, scope/model
mismatch, outcome/Oracle/generated-code fields in attestation, and double-counted contrast IDs.

- [ ] **Step 2: Run role/target tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_prompt_role_attestations.py tests/test_target_materialization.py tests/test_preflight.py
```

Expected: FAIL because roles, attestations, and target materialization do not exist.

- [ ] **Step 3: Extend prompt records and create exact attestation records**

Add required `prompt_role` and optional `counterpart_prompt_id` to `PromptRecord`. Validation rules:

```python
@model_validator(mode="after")
def validate_prompt_role(self) -> "PromptRecord":
    variant_roles = {
        PromptRole.POSITIVE_SAFETY_CONTROL,
        PromptRole.TASK_FUNCTION_VARIANT,
        PromptRole.PRESENTATION_VARIANT,
    }
    if self.prompt_role in variant_roles:
        if self.counterpart_prompt_id is None:
            raise ValueError("variant prompts require an exact baseline counterpart")
    elif self.counterpart_prompt_id is not None:
        raise ValueError("only variant prompts may name a counterpart")
    return self
```

Extend `DataConfig` with
`functional_outcome_contracts_path: str | None = None`. Preflight reads and validates this optional
pre-outcome contract artifact; it is never an outcome result. The M5 demo leaves it unset and uses
the required three-arm task protocol.

Persist exact pre-outcome attestations:

```python
class PromptRoleAttestationRecord(VersionedModel):
    schema_version: Literal["1.0"]
    attestation_id: str = Field(pattern=r"^attestation_[0-9a-f]{64}$")
    prompt_id: str
    task_id: str
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_role: PromptRole
    counterpart_prompt_id: str | None
    counterpart_prompt_sha256: str | None
    variant_clause_start: int | None
    variant_clause_end: int | None
    variant_clause_sha256: str | None
    contrast_owner_operation: FeatureOperation
    catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
```

The variant clause range must be the only byte difference between variant and baseline text, and
removing it must restore baseline text byte-for-byte. The attestation pre-registers exactly one
`contrast_owner_operation`; the reverse view retains the same `contrast_id` for audit but cannot
materialize a second assignable protocol. Attestations contain no CWE outcome label, generated code,
arm, expected effect, or Oracle data.

- [ ] **Step 4: Update demo pairs and implement target materialization**

Make each confirm baseline/variant pair share one `task_id`; the variant prompt must be the exact
baseline text plus one catalog clause. Give different demo pairs different pre-registered owner
operations so both ADD and REMOVE paths are exercised without double-counting one pair, with at least
two independent task pairs for every exercised semantic protocol. Discovery
prompts retain one task ID per source prompt. Add
`data.prompt_attestations_path` to strict config and validate the complete confirm-prompt coverage in
preflight.

```python
def materialize_target_spec(
    hypothesis: FrozenHypothesisRecord,
    operation: FeatureOperation,
) -> TargetSpecRecord:
    revalidate_frozen_hypothesis(hypothesis)
    require_permitted_operation(hypothesis, operation)
    expected = expected_contrast_for(hypothesis, operation)
    return TargetSpecRecord.from_content(
        hypothesis_id=hypothesis.hypothesis_id,
        frozen_hypothesis_sha256=hypothesis.hypothesis_sha256,
        feature_family=hypothesis.feature_family,
        feature_id=hypothesis.target_feature_id,
        operation=operation,
        hypothesis_outcome_variable_id=hypothesis.outcome_variable_id,
        hypothesis_outcome_estimand_id=expected.outcome_estimand_id,
        expected_hypothesis_contrast_sign=expected.expected_sign,
    )


def materialize_target_instance(
    target: TargetSpecRecord,
    hypothesis: FrozenHypothesisRecord,
    prompt: PromptRecord,
    attestations: Sequence[PromptRoleAttestationRecord],
) -> TargetInstanceRecord:
    require_target_matches_hypothesis(target, hypothesis)
    require_confirm_scope(hypothesis, prompt)
    operation = target.operation
    require_contrast_owner_operation(prompt, attestations, operation)
    require_prompt_role_for_family_operation(prompt, hypothesis.feature_family, operation)
    require_counterpart_when_needed(prompt, attestations, operation)
    return TargetInstanceRecord.from_content(
        target_spec_id=target.target_spec_id,
        task_id=prompt.task_id,
        source_prompt_id=prompt.prompt_id,
        source_prompt_sha256=prompt.prompt_sha256,
        counterpart_prompt_id=counterpart_id_for(prompt, attestations),
        counterpart_prompt_sha256=counterpart_sha256_for(prompt, attestations),
        source_prompt_role=prompt.prompt_role,
        counterpart_required=operation is FeatureOperation.REMOVE,
    )
```

`materialize_protocol_instance(protocol, target_instance)` revalidates both semantic records and binds
the exact task/source/counterpart digests without changing `target_spec_id` or `arm_protocol_id`.

- [ ] **Step 5: Re-run preflight/target tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_prompt_role_attestations.py tests/test_target_materialization.py tests/test_preflight.py tests/test_schema.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/schema/records.py src/secaware/intervention/attestation.py src/secaware/intervention/targeting.py src/secaware/config.py data/examples configs tests/test_prompt_role_attestations.py tests/test_target_materialization.py tests/test_preflight.py
git commit -m "feat: bind prompt roles and intervention targets"
```

### Task 3: Implement deterministic and LLM executors for text-native and graph-native modes

**Files:**
- Create: `src/secaware/intervention/executors.py`
- Create: `src/secaware/intervention/graph_patch.py`
- Create: `src/secaware/intervention/prompts/intervention_executor_v1.txt`
- Modify: `src/secaware/config.py`
- Modify: `pyproject.toml`
- Create: `tests/test_intervention_executors.py`
- Create: `tests/test_graph_native_intervention.py`
- Create: `tests/test_llm_intervention_security.py`

- [ ] **Step 1: Write failing executor/mode/security tests**

```python
def test_text_native_llm_executor_receives_target_but_no_outcome() -> None:
    transport = CapturingTransport(_candidate_response())
    candidate = LLMInterventionExecutor(transport).execute(_text_native_request())
    payload = json.loads(transport.requests[0].decode("utf-8"))
    assert payload["target_spec_id"] == _target().target_spec_id
    assert "oracle" not in payload
    assert "expected_outcome" not in payload
    assert "generated_code" not in payload
    assert candidate.mode is InterventionMode.TEXT_NATIVE


def test_graph_native_executor_records_intended_patch_before_rendering() -> None:
    patch, candidate = GraphNativeExecutor(_renderer()).execute(_graph_native_request())
    assert patch.before_graph_sha256 == _source_graph().graph_sha256
    assert patch.target_spec_id == _target().target_spec_id
    assert candidate.intended_patch_id == patch.patch_id
```

Cover all arm roles, exact safety REMOVE restoration, no unsafe wording, positive-polarity safety ADD,
one candidate, no semantic retry, identical-byte transport retry, prompt injection, extra target,
catalog escape, executor self-judgment, code/Oracle leakage, response bounds, model/template drift,
graph patch mutation, and separate executor/extractor template hashes.

- [ ] **Step 2: Run executor tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_intervention_executors.py tests/test_graph_native_intervention.py tests/test_llm_intervention_security.py
```

Expected: FAIL because executor and graph-patch modules do not exist.

- [ ] **Step 3: Add strict run-wide intervention configuration**

```python
class InterventionLLMConfig(StrictModel):
    model_id: str = Field(min_length=1, max_length=256)
    base_url: str = Field(min_length=1, max_length=2048, repr=False)
    api_key_env: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$", repr=False)
    timeout_seconds: float = Field(default=60.0, gt=0.0, le=3600.0)
    max_attempts: int = Field(default=3, ge=1, le=10)
    max_response_bytes: int = Field(default=262_144, ge=1024, le=1_048_576)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    top_p: float = Field(default=1.0, gt=0.0, le=1.0)
    seed: int | None = 0


class InterventionConfig(StrictModel):
    mode: InterventionMode = InterventionMode.TEXT_NATIVE
    executor: InterventionExecutorKind = InterventionExecutorKind.LLM
    llm: InterventionLLMConfig | None = None
    operations: tuple[FeatureOperation, ...] = (FeatureOperation.ADD, FeatureOperation.REMOVE)
    max_protocols: int = Field(default=64, ge=1, le=512)
```

The `AppConfig` validator requires a distinct LLM policy when executor is LLM and forbids an LLM
policy for the deterministic executor. Extractor and executor model/template/policy digests remain
separate even if they happen to name the same provider model.

- [ ] **Step 4: Implement deterministic clauses, LLM requests, and graph patches**

The deterministic executor uses only finite positive catalog clauses and exact attested removal
ranges. The LLM executor emits a strict request containing source prompt as inert data, target,
operation, arm role, `AllowedDelta`, and output schema; it receives no code, Oracle result, expected
effect sign, or confirmation status.

```python
class IntendedGraphPatchRecord(VersionedModel):
    schema_version: Literal["1.0"]
    patch_id: str = Field(pattern=r"^patch_[0-9a-f]{64}$")
    target_spec_id: str = Field(pattern=r"^target_[0-9a-f]{64}$")
    target_instance_id: str = Field(pattern=r"^target_instance_[0-9a-f]{64}$")
    arm_protocol_id: str = Field(pattern=r"^arm_protocol_[0-9a-f]{64}$")
    protocol_instance_id: str = Field(pattern=r"^protocol_instance_[0-9a-f]{64}$")
    arm_role: ArmRole
    before_graph_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    allowed_delta_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    intended_transitions: tuple[FeatureTransition, ...]


class PromptCandidate(StrictModel):
    source_prompt_id: str
    target_spec_id: str
    target_instance_id: str
    arm_protocol_id: str
    protocol_instance_id: str
    arm_role: ArmRole
    mode: InterventionMode
    executor_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    intended_patch_id: str | None
    text: str = Field(min_length=1, max_length=262_144, repr=False)
```

Text-native execution edits source text directly. Graph-native execution first commits an intended
patch object, then renders it into text. Neither mode mutates the committed source Prompt TSG.

- [ ] **Step 5: Re-run executor/mode/security tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_intervention_executors.py tests/test_graph_native_intervention.py tests/test_llm_intervention_security.py tests/test_structured_llm_transport.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/intervention/executors.py src/secaware/intervention/graph_patch.py src/secaware/intervention/prompts/intervention_executor_v1.txt src/secaware/config.py pyproject.toml tests/test_intervention_executors.py tests/test_graph_native_intervention.py tests/test_llm_intervention_security.py
git commit -m "feat: add locked prompt intervention executors"
```

### Task 4: Independently extract, validate, and freeze complete prompt protocols

**Files:**
- Create: `src/secaware/intervention/variant_validation.py`
- Create: `src/secaware/pipeline/stages/prompt_variants.py`
- Modify: `src/secaware/schema/experiments.py`
- Modify: `src/secaware/io/run_store.py`
- Create: `tests/test_allowed_delta_validation.py`
- Create: `tests/test_length_match_validation.py`
- Create: `tests/test_security_neutral_prompt_invariant.py`
- Create: `tests/test_prompt_variant_freeze_stage.py`

- [ ] **Step 1: Write failing hard-gate versus diagnostic tests**

```python
def test_target_not_changed_is_frozen_as_diagnostic_not_hard_failure() -> None:
    candidate = _safe_candidate_with_no_target_change()
    result = validate_variant(candidate, _source(), _protocol(), _independent_extractor())
    assert result.hard_valid is True
    assert result.target_changed is False
    assert result.semantic_compliance is False
    assert result.variant is not None


def test_undeclared_safety_change_fails_the_whole_protocol_before_randomization() -> None:
    with pytest.raises(ProtocolFreezeError):
        freeze_protocol_variants(_protocol_with_one_cross_family_drift())
    assert not _assignment_manifest_exists()
```

Cover exact graph round trip, feature transition subset, fixed families, fixed feature IDs, sentinel
features for unsafe request/vulnerability disclosure/outcome leakage, target diagnostic false/unknown,
permissible presentation placebo drift, extractor blindness to arm/target, extractor policy mismatch,
one-arm failure excluding the whole block, no candidate replacement, duplicate variants, prompt text
hash, source task/split mismatch, forward/reverse contrast de-duplication, changed-span UTF-8 byte
measurement, the 5%/four-byte tolerance boundary, length-match record mutation, semantic definition
reuse across tasks, target/protocol instance coverage, and transaction rollback.

- [ ] **Step 2: Run variant gate/stage tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_allowed_delta_validation.py tests/test_length_match_validation.py tests/test_security_neutral_prompt_invariant.py tests/test_prompt_variant_freeze_stage.py
```

Expected: FAIL because independent validation and freeze stage do not exist.

- [ ] **Step 3: Implement graph delta and neutrality validation**

```python
def security_neutral_prompt_invariant(
    graph: nx.MultiDiGraph,
    attestation: PromptRoleAttestationRecord,
) -> bool:
    sentinels = (
        "safety.prohibited_unsafe_request",
        "safety.vulnerability_disclosure",
        "safety.expected_outcome_leakage",
    )
    return all(feature_state(graph, feature_id) is FeatureState.ABSENT for feature_id in sentinels) and attestation_is_current(attestation)


def actual_feature_transitions(
    before: nx.MultiDiGraph,
    after: nx.MultiDiGraph,
) -> tuple[FeatureTransition, ...]:
    transitions = []
    for feature_id in catalog_feature_ids():
        old = feature_state(before, feature_id)
        new = feature_state(after, feature_id)
        if old is not new:
            transitions.append(FeatureTransition(feature_id=feature_id, from_states=(old,), to_states=(new,)))
    return tuple(sorted(transitions, key=lambda item: item.feature_id))
```

Require every actual transition to be permitted by `AllowedDelta`; require fixed families/features to
be unchanged. The target transition need not occur. Any unresolved neutrality sentinel or unresolved
fixed projection is a hard pre-randomization failure.

- [ ] **Step 4: Persist complete frozen artifacts**

Add these records:

```python
class GraphDeltaRecord(VersionedModel):
    schema_version: Literal["1.0"]
    delta_id: str = Field(pattern=r"^delta_[0-9a-f]{64}$")
    target_spec_id: str
    target_instance_id: str
    arm_protocol_id: str
    protocol_instance_id: str
    arm_role: ArmRole
    before_graph_sha256: str
    after_graph_sha256: str
    actual_transitions: tuple[FeatureTransition, ...]
    target_changed: bool | None
    semantic_compliance: bool | None
    permissible_non_target_drift: tuple[str, ...]
    length_match_id: str | None


class PromptVariantRecord(VersionedModel):
    schema_version: Literal["1.0"]
    variant_id: str = Field(pattern=r"^variant_[0-9a-f]{64}$")
    task_id: str
    source_prompt_id: str
    variant_prompt_id: str
    hypothesis_id: str
    target_spec_id: str
    target_instance_id: str
    arm_protocol_id: str
    protocol_instance_id: str
    arm_role: ArmRole
    prompt_sha256: str
    prompt_text: str = Field(repr=False)
    proposal_id: str
    graph_id: str
    delta_id: str
    executor_policy_sha256: str
    extractor_policy_sha256: str
    length_match_id: str | None
```

Persist the deterministic length-match decision separately and bind it from the affected variant and
delta records:

```python
class LengthMatchRecord(VersionedModel):
    schema_version: Literal["1.0"]
    length_match_id: str = Field(pattern=r"^length_match_[0-9a-f]{64}$")
    arm_protocol_id: str = Field(pattern=r"^arm_protocol_[0-9a-f]{64}$")
    protocol_instance_id: str = Field(pattern=r"^protocol_instance_[0-9a-f]{64}$")
    reference_arm_role: ArmRole
    matched_arm_role: ArmRole
    metric: Literal["canonical_changed_span_utf8_bytes_v1"]
    reference_delta_bytes: int = Field(ge=0)
    matched_delta_bytes: int = Field(ge=0)
    tolerance_bytes: int = Field(ge=4)
    within_tolerance: Literal[True]
```

For each finite matched role (`LENGTH_MATCHED_PLACEBO`, `LENGTH_MATCHED_SHAM_EDIT`,
`TASK_LENGTH_PLACEBO`, or `PRESENTATION_MATCHED_CONTROL`), compare its changed-span UTF-8 byte length
with the target arm's changed span. Compute one canonical minimal contiguous edit by stripping the
longest common UTF-8 byte prefix and then the longest non-overlapping common suffix; its footprint is
`deleted_middle_bytes + inserted_middle_bytes`. Set
`tolerance_bytes = max(4, ceil(reference_delta_bytes * 0.05))`; exceeding it is a hard
pre-randomization protocol failure. Require `length_match_id` exactly for those roles and verify the
record against the frozen prompt bytes rather than trusting executor output.

The stage publishes `target_specs.jsonl`, `target_instances.jsonl`, `confirmation_protocols.jsonl`,
`confirmation_protocol_instances.jsonl`, `intended_patches.jsonl`,
`variant_extraction_proposals.jsonl`, `variant_prompt_tsg.jsonl`, `graph_deltas.jsonl`,
`prompt_variants.jsonl`, `length_matches.jsonl`, and `pre_randomization_exclusions.jsonl` atomically. Exact protocol coverage
is checked after readback. A hard-invalid protocol has no variant records and one typed exclusion;
safe diagnostic noncompliance remains frozen.
Persist each semantic TargetSpec/protocol once per hypothesis/operation, while emitting one instance
pair per eligible task. Reject any instance that changes semantic content or any semantic definition
whose frozen-hypothesis digest is stale.

- [ ] **Step 5: Re-run variant/stage/transaction tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_allowed_delta_validation.py tests/test_length_match_validation.py tests/test_security_neutral_prompt_invariant.py tests/test_prompt_variant_freeze_stage.py tests/test_jsonl_stage_transaction.py tests/test_prompt_extraction_security.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/intervention/variant_validation.py src/secaware/pipeline/stages/prompt_variants.py src/secaware/schema/experiments.py src/secaware/io/run_store.py tests/test_allowed_delta_validation.py tests/test_length_match_validation.py tests/test_security_neutral_prompt_invariant.py tests/test_prompt_variant_freeze_stage.py
git commit -m "feat: freeze validated prompt arm protocols"
```

### Task 5: Add deterministic complete-block randomization and immutable assignments

**Files:**
- Create: `src/secaware/experiments/__init__.py`
- Create: `src/secaware/experiments/randomization.py`
- Create: `src/secaware/pipeline/stages/randomization.py`
- Modify: `src/secaware/schema/experiments.py`
- Modify: `src/secaware/config.py`
- Modify: `configs/demo.yaml`
- Modify: `configs/paper_v0.yaml`
- Create: `tests/test_confirmation_randomization.py`
- Create: `tests/test_randomization_stage.py`

- [ ] **Step 1: Write failing unit/block/balance tests**

```python
def test_assignment_maps_seed_slot_unit_to_arm_role() -> None:
    manifest, assignments = randomize_protocols(_four_arm_variants(), _randomization_config())
    assignment = assignments[0]
    assert assignment.experimental_unit.seed_slot >= 0
    assert assignment.arm_role in set(_four_arm_protocol().arm_roles)
    assert assignment.experimental_unit.target_spec_id == assignment.target_spec_id


def test_add_remove_and_protocols_never_share_blocks() -> None:
    _manifest, assignments = randomize_protocols(_add_and_remove_variants(), _randomization_config())
    blocks = group_assignments_by_block(assignments)
    assert all(len({item.target_spec_id for item in block}) == 1 for block in blocks.values())
    assert all(len({item.arm_protocol_id for item in block}) == 1 for block in blocks.values())


def test_task_blocks_share_semantic_protocol_but_keep_distinct_instances() -> None:
    _manifest, assignments = randomize_protocols(_same_protocol_two_tasks(), _randomization_config())
    assert len({item.target_spec_id for item in assignments}) == 1
    assert len({item.arm_protocol_id for item in assignments}) == 1
    assert len({item.target_instance_id for item in assignments}) == 2
    assert len({item.protocol_instance_id for item in assignments}) == 2
```

Cover exact block key, no `arm_role` inside the pre-assignment unit, balanced permutations, seed-slot
count divisible by every active arm count, mixed three/four-arm protocols succeeding with the default
12 slots, an invalid non-common-multiple configuration failing before assignment, deterministic
input-order invariance, RNG/version drift, duplicate
assignment IDs, variant omission/extra, partial protocol, task/model/hypothesis/target mismatch,
provider order independence, no outcomes read, immutable committed assignments, and rollback.
Require exactly one target/protocol instance per task-level block and reject an instance whose semantic
IDs or source task do not match the block. Reject a semantic protocol family below the configured
independent-task minimum.

- [ ] **Step 2: Run randomization tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_confirmation_randomization.py tests/test_randomization_stage.py
```

Expected: FAIL because randomization modules do not exist.

- [ ] **Step 3: Implement exact experimental-unit and assignment records**

```python
class ExperimentalUnit(StrictModel):
    task_id: str
    hypothesis_id: str
    target_spec_id: str
    model_id: str
    seed_slot: int = Field(ge=0)


class AssignmentRecord(VersionedModel):
    schema_version: Literal["1.0"]
    assignment_id: str = Field(pattern=r"^assignment_[0-9a-f]{64}$")
    block_id: str = Field(pattern=r"^block_[0-9a-f]{64}$")
    experimental_unit: ExperimentalUnit
    target_spec_id: str
    target_instance_id: str
    arm_protocol_id: str
    protocol_instance_id: str
    variant_id: str
    arm_role: ArmRole
    seed_id: int
    rng_version: Literal["sha256-rejection-fisher-yates-v1"]
    randomization_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class RandomizationManifestRecord(VersionedModel):
    schema_version: Literal["1.0"]
    manifest_id: str = Field(pattern=r"^randomization_[0-9a-f]{64}$")
    global_seed: int
    rng_version: Literal["sha256-rejection-fisher-yates-v1"]
    randomization_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    block_ids: tuple[str, ...]
    assignment_ids: tuple[str, ...]
    assignments_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
```

Add bounded configuration without reusing observational seeds:

```python
class RandomizationConfig(StrictModel):
    rng_version: Literal["sha256-rejection-fisher-yates-v1"] = "sha256-rejection-fisher-yates-v1"
    max_blocks: int = Field(default=10_000, ge=1, le=100_000)
    min_independent_tasks_per_semantic_protocol: int = Field(default=20, ge=2, le=100_000)
```

Extend the existing `GenerationConfig` with
`confirmation_seeds: list[int] = Field(default_factory=lambda: list(range(101, 113)))`. Validate
unique, nonempty, bounded confirmation seeds. Before freezing the randomization plan, require the
configured count to be divisible by every active protocol arm count; the closed 2/3/4-arm catalog
therefore uses a 12-slot default. Demo and paper configs explicitly declare 12 confirmation seeds;
the paper config keeps the 20-task minimum, while the tiny offline demo explicitly sets the minimum to
2 and contains two task instances for its exercised semantic protocol. Observational `seeds` remain unchanged. Add
`randomization: RandomizationConfig = Field(default_factory=RandomizationConfig)` to `AppConfig`.

- [ ] **Step 4: Implement balanced block assignment and the stage**

The block key is exactly `(task_id, hypothesis_id, target_spec_id, arm_protocol_id, model_id)`. Sort all
blocks and variants. For each block, repeat the protocol's sorted arm tuple until it fills configured
confirmation-seed slots, then shuffle with a `DeterministicRNG` derived from global seed plus block ID.
First compute `randomization_plan_sha256` from the pre-assignment block/variant/seed/config payload;
assignments reference that acyclic plan digest. Map each
sorted seed slot to one role and its exact frozen variant. Commit the manifest and assignments in one
transaction before any generation request is planned.

Resolve one `TargetInstanceRecord` and `ConfirmationProtocolInstanceRecord` for each task-level block
before assignment and copy their IDs into every assignment. Instance IDs distinguish task/prompt
realizations but do not split the semantic TargetSpec/arm-protocol analysis family.

Before committing any assignment, require every semantic
`(hypothesis_id, target_spec_id, arm_protocol_id, model_id)` family to contain at least
`min_independent_tasks_per_semantic_protocol` distinct task IDs. Insufficient support is a typed
pre-randomization failure, never a one-task estimand.

Reject blocks whose seed-slot count is not a positive multiple of arm count. Do not silently trim
seeds or reuse a slot.

- [ ] **Step 5: Re-run randomization and RNG tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_confirmation_randomization.py tests/test_randomization_stage.py tests/test_deterministic_randomness.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/experiments src/secaware/pipeline/stages/randomization.py src/secaware/schema/experiments.py src/secaware/config.py configs/demo.yaml configs/paper_v0.yaml tests/test_confirmation_randomization.py tests/test_randomization_stage.py
git commit -m "feat: add randomized confirmation assignments"
```

### Task 6: Add assignment-bound generation requests and exact execution coverage

**Files:**
- Modify: `src/secaware/schema/generation.py`
- Modify: `src/secaware/schema/records.py`
- Modify: `src/secaware/schema/migrations.py`
- Modify: `src/secaware/schema/experiments.py`
- Modify: `src/secaware/generation/request_planner.py`
- Modify: `src/secaware/generation/openai_compatible_provider.py`
- Create: `src/secaware/pipeline/stages/confirmation_generation.py`
- Create: `tests/test_generation_schema_v12.py`
- Create: `tests/test_confirmation_generation_planner.py`
- Create: `tests/test_confirmation_generation_stage.py`
- Modify: `tests/test_generation_planner.py`
- Modify: `tests/test_generation_cli.py`
- Modify: `tests/test_provider_generation_cli.py`
- Modify: `tests/test_openai_compatible_provider.py`

- [ ] **Step 1: Write failing request/execution/coverage tests**

```python
def test_confirmation_request_binds_assignment_variant_and_arm() -> None:
    request = plan_confirmation_requests(_assignments(), _variants(), _generation_config())[0]
    assert request.schema_version == "1.2"
    assert request.condition == "confirm_arm"
    assert request.assignment_id == _assignments()[0].assignment_id
    assert request.target_instance_id == _assignments()[0].target_instance_id
    assert request.arm_protocol_id == _assignments()[0].arm_protocol_id
    assert request.protocol_instance_id == _assignments()[0].protocol_instance_id
    assert request.variant_id == _assignments()[0].variant_id
    assert request.arm_role == _assignments()[0].arm_role


def test_valid_terminal_generation_failure_keeps_assignment_coverage(tmp_path) -> None:
    records, codes = execute_confirmation_requests(
        _requests(),
        _provider_with_one_content_filter(),
    )
    assert {item.assignment_id for item in records} == {item.assignment_id for item in _requests()}
    assert sum(item.status is AssignmentExecutionStatus.TERMINAL_NO_CODE for item in records) == 1
    assert len(codes) == len(records) - 1
```

Cover request-ID mutation, prompt/variant hash mismatch, assignment/arm/seed drift, legacy 1.1
migration, observed request invariants, duplicate/omitted/extra executions, generated-code subset
coverage, content-filter terminal result, auth/model/transport infrastructure abort, retry exhaustion,
partial output rollback, assignment manifest replacement, and provider execution-order invariance.

- [ ] **Step 2: Run generation tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_generation_schema_v12.py tests/test_confirmation_generation_planner.py tests/test_confirmation_generation_stage.py tests/test_generation_planner.py tests/test_generation_cli.py tests/test_provider_generation_cli.py tests/test_openai_compatible_provider.py
```

Expected: FAIL because schema 1.2 and confirmation generation do not exist.

- [ ] **Step 3: Extend generation records without weakening observed contracts**

Set `GENERATION_REQUEST_SCHEMA_VERSION = "1.2"`. Add:

```python
GenerationCondition = Literal["observed", "confirm_arm"]
EndpointType = Literal["mock", "offline", "chat_completions"]


class GenerationRequestRecord(SafeValidationMixin, VersionedModel):
    schema_version: Literal["1.2"]
    request_id: str
    condition: GenerationCondition
    prompt_id: str
    prompt: str = Field(repr=False)
    prompt_sha256: str
    language: str
    model_id: str
    seed_id: int
    hypothesis_id: str | None = None
    assignment_id: str | None = None
    target_spec_id: str | None = None
    target_instance_id: str | None = None
    arm_protocol_id: str | None = None
    protocol_instance_id: str | None = None
    variant_id: str | None = None
    arm_role: ArmRole | None = None
    endpoint_type: EndpointType
    endpoint_sha256: str
    system_template_version: str
    system_template_sha256: str
    parameters: GenerationParameters
```

Observed requests require all experiment fields absent. Confirm-arm requests require all experiment
fields present and mutually consistent. Extend canonical generated code records with the same
coordinates and bump their strict schema to 1.1. Migrate valid legacy observed 1.1 requests/code
records; reject legacy counterfactual records from the new stage with a documented regeneration
error.

- [ ] **Step 4: Implement confirmation planning and terminal execution records**

```python
class AssignmentExecutionStatus(str, Enum):
    GENERATED = "generated"
    TERMINAL_NO_CODE = "terminal_no_code"


class AssignmentExecutionRecord(VersionedModel):
    schema_version: Literal["1.0"]
    assignment_id: str
    request_id: str
    status: AssignmentExecutionStatus
    code_id: str | None
    terminal_reason: Literal["content_filter"] | None
```

Plan one request for every assignment from its frozen variant. Execute in any provider order, but
sort outputs canonically. A valid provider `finish_reason="content_filter"` becomes
`TERMINAL_NO_CODE`; authentication, endpoint/model drift, malformed protocol, timeout exhaustion,
and missing provider remain infrastructure errors that abort and preserve the prior commit.

Publish `generation/confirmation_requests.jsonl`, `generation/confirmation_execution.jsonl`, and
`generation/confirmation_code.jsonl` transactionally. Execution IDs must exactly cover assignments;
code IDs must exactly cover GENERATED executions.

- [ ] **Step 5: Re-run generation schema/provider/stage tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_generation_schema_v12.py tests/test_confirmation_generation_planner.py tests/test_confirmation_generation_stage.py tests/test_generation_planner.py tests/test_generation_cli.py tests/test_provider_generation_cli.py tests/test_openai_compatible_provider.py tests/test_generation_result_importer.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/schema/generation.py src/secaware/schema/records.py src/secaware/schema/migrations.py src/secaware/schema/experiments.py src/secaware/generation/request_planner.py src/secaware/generation/openai_compatible_provider.py src/secaware/pipeline/stages/confirmation_generation.py tests/test_generation_schema_v12.py tests/test_confirmation_generation_planner.py tests/test_confirmation_generation_stage.py tests/test_generation_planner.py tests/test_generation_cli.py tests/test_provider_generation_cli.py tests/test_openai_compatible_provider.py
git commit -m "feat: bind randomized assignments to generation"
```

### Task 7: Generalize the independent Oracle to confirmation assignments

**Files:**
- Modify: `src/secaware/schema/oracle.py`
- Modify: `src/secaware/oracle/aggregator.py`
- Modify: `src/secaware/oracle/cli.py`
- Modify: `src/secaware/cli.py`
- Create: `src/secaware/pipeline/stages/confirmation_oracle.py`
- Create: `tests/test_confirmation_oracle.py`
- Modify: `tests/test_oracle_schema_v1.py`
- Modify: `tests/test_oracle_engine.py`
- Modify: `tests/test_oracle_cli.py`

- [ ] **Step 1: Write failing assignment-provenance Oracle tests**

```python
def test_confirmation_oracle_preserves_all_assignment_coordinates() -> None:
    code = _confirmation_code()
    record = run_oracle_batch([code], _policy(), runner=_realistic_fake_runner())[0]
    assert record.condition == "confirm_arm"
    assert record.assignment_id == code.assignment_id
    assert record.target_instance_id == code.target_instance_id
    assert record.arm_protocol_id == code.arm_protocol_id
    assert record.protocol_instance_id == code.protocol_instance_id
    assert record.variant_id == code.variant_id
    assert record.arm_role == code.arm_role


def test_oracle_coverage_matches_generated_execution_subset() -> None:
    validate_confirmation_oracle_coverage(_assignments(), _executions(), _codes(), _oracles())
    with pytest.raises(SecAwareError):
        validate_confirmation_oracle_coverage(
            _assignments(),
            _executions(),
            _codes(),
            _oracles_with_one_missing(),
        )
```

Cover observed/confirm discriminator rules, assignment/variant/arm/seed drift, terminal-no-code having
no Oracle record, Oracle extra/duplicate, code hash mutation, analyzer policy drift, missing real
Semgrep/Bandit, fail-closed subprocess errors, partial transaction rollback, and raw code/prompt not
appearing in public errors.

- [ ] **Step 2: Run Oracle confirmation tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_confirmation_oracle.py tests/test_oracle_schema_v1.py tests/test_oracle_engine.py tests/test_oracle_cli.py
```

Expected: FAIL because Oracle records do not carry confirmation coordinates.

- [ ] **Step 3: Extend Oracle records and aggregation**

Add optional `assignment_id`, `target_spec_id`, `target_instance_id`, `arm_protocol_id`,
`protocol_instance_id`, `variant_id`, and `arm_role` fields to
`OracleRecord` and bump its strict schema from M4B's 1.1 to 1.2. Observed records require them absent; confirm-arm
records require them present along with `hypothesis_id`. Copy coordinates only from the revalidated
canonical generated-code record.
Preserve the M4B `OracleEvaluability` and typed UNKNOWN invariants unchanged, and migrate valid
schema-1.1 observed records only.
Finding adapters remain blind to assignments.

Do not reintroduce lightweight rules. Both conditions use the same locked Semgrep/Bandit policy and
the same independent process runner.

- [ ] **Step 4: Implement the confirmation Oracle stage**

Hold committed assignment, execution, code, and generation-stage manifests. Require code coverage to
match GENERATED executions before invoking analyzers. Publish `oracle/confirmation_oracle.jsonl` and
require exact Oracle coverage after readback. A terminal-no-code execution intentionally has no
Oracle record; a missing Oracle for generated code aborts.

Register `run-oracle --condition confirmation` and map it internally to the canonical
`confirm_arm` condition. Preserve observed behavior.

- [ ] **Step 5: Re-run Oracle and real-tool gates**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_confirmation_oracle.py tests/test_oracle_schema_v1.py tests/test_oracle_engine.py tests/test_oracle_cli.py tests/test_oracle_real_tools.py
```

Expected: PASS; real-tool tests skip only when their exact capability marker is unavailable.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/schema/oracle.py src/secaware/oracle/aggregator.py src/secaware/oracle/cli.py src/secaware/cli.py src/secaware/pipeline/stages/confirmation_oracle.py tests/test_confirmation_oracle.py tests/test_oracle_schema_v1.py tests/test_oracle_engine.py tests/test_oracle_cli.py
git commit -m "feat: run independent oracle on randomized assignments"
```

### Task 8: Register the M5 pipeline, remove two-arm CLI surfaces, document, and verify

**Files:**
- Modify: `src/secaware/pipeline/stages/__init__.py`
- Modify: `src/secaware/io/run_store.py`
- Modify: `src/secaware/cli.py`
- Modify: `README.md`
- Create: `docs/migrations/randomized-confirmation.md`
- Create: `tests/test_m5_architecture.py`
- Modify: `tests/test_stage_orchestration.py`
- Modify: `tests/test_run_all_demo.py`
- Modify: `tests/test_packaging.py`

- [ ] **Step 1: Write failing CLI, orchestration, and architecture gates**

```python
def test_m5_has_no_code_tsg_or_unsafe_remove_surface() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in Path("src/secaware").rglob("*.py"))
    assert "CodeTSG" not in source
    assert "code_mechanism" not in source
    assert "skip validation" not in source.casefold()
    assert "use an unsafe" not in source.casefold()


def test_randomization_cannot_import_outcomes_or_oracle() -> None:
    imports = imported_symbols(Path("src/secaware/experiments/randomization.py"))
    assert all("oracle" not in item and "outcome" not in item for item in imports)


def test_semantic_target_and_protocol_types_have_no_task_prompt_coordinates() -> None:
    forbidden = {"task_id", "source_prompt_id", "counterpart_prompt_id"}
    assert forbidden.isdisjoint(TargetSpecRecord.model_fields)
    assert forbidden.isdisjoint(ConfirmationProtocolRecord.model_fields)
    assert {"task_id", "source_prompt_id"} <= set(TargetInstanceRecord.model_fields)
    assert {"task_id", "source_prompt_id"} <= set(ConfirmationProtocolInstanceRecord.model_fields)


def test_m5_commands_replace_legacy_two_arm_surface() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "build-confirmation-variants" in result.stdout
    assert "randomize-confirmation" in result.stdout
    assert "generate-confirmation" in result.stdout
    assert "generate-counterfactual" not in result.stdout
```

Also assert executor and extractor system-template hashes differ, variant extractor requests lack arm
and target, one forward/reverse contrast cannot appear twice, and no primary-ITT filter exists in M5.

- [ ] **Step 2: Run the new integration gates and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_m5_architecture.py tests/test_stage_orchestration.py tests/test_run_all_demo.py tests/test_packaging.py
```

Expected: FAIL because the new commands/run order are not registered and legacy surfaces remain.

- [ ] **Step 3: Register commands, extend `run-all`, and document migration behavior**

Expose `build-confirmation-variants`, `randomize-confirmation`, `generate-confirmation`, and
`run-oracle --condition confirmation`. Remove `intervene` and `generate-counterfactual` from Typer
registration. `run-all` order becomes:

```text
prepare
extract-prompt-tsg
generate observed discovery code
run observed Oracle
assemble causal tables
discover/freeze FCI hypotheses
build/freeze confirmation variants
randomize confirmation
generate confirmation assignments
run confirmation Oracle
```

M6 adds analysis/JCI/reporting. Each stage holds sorted producer leases and is included in
`RunStore` sealing/directory logic.

Document source prompt roles, exact positive/neutral counterparts, `SecurityNeutralPromptInvariant`,
per-arm `AllowedDelta`, hard pre-randomization exclusion versus diagnostics, text/graph modes, LLM
executor simplifying assumption, separate extractor role, complete blocks, seed slots, assignment
commit point, terminal-no-code handling, and removal of two-arm artifacts/commands.

- [ ] **Step 4: Run focused M5 gates**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_experiment_schema.py tests/test_arm_protocol_catalog.py tests/test_prompt_role_attestations.py tests/test_target_materialization.py tests/test_intervention_executors.py tests/test_graph_native_intervention.py tests/test_llm_intervention_security.py tests/test_allowed_delta_validation.py tests/test_length_match_validation.py tests/test_security_neutral_prompt_invariant.py tests/test_prompt_variant_freeze_stage.py tests/test_confirmation_randomization.py tests/test_randomization_stage.py tests/test_generation_schema_v12.py tests/test_confirmation_generation_planner.py tests/test_confirmation_generation_stage.py tests/test_confirmation_oracle.py tests/test_m5_architecture.py
```

Expected: PASS.

- [ ] **Step 5: Run full regression and static gates**

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format --check src tests
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m secaware --help
git diff --check
if (Test-Path uv.lock) { throw 'uv.lock must not exist' }
```

Expected: all commands exit zero. `tests/test_run_all_demo.py` proves that `run-all` stops after
committed confirmation Oracle artifacts under injected real-contract fakes and never creates
pair/effect/JCI/report artifacts before M6. Run the separately marked real-Oracle gate only in an
environment with the exact locked Semgrep/Bandit capability.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/pipeline/stages/__init__.py src/secaware/io/run_store.py src/secaware/cli.py README.md docs/migrations/randomized-confirmation.md tests/test_m5_architecture.py tests/test_stage_orchestration.py tests/test_run_all_demo.py tests/test_packaging.py
git commit -m "docs: complete randomized confirmation pipeline"
```

## M5 self-review checklist

- Target family/feature/operation and arm role are separate persisted dimensions.
- Semantic target/protocol IDs are shared across tasks; prompt-bound instance IDs are never analysis
  grouping keys.
- Protocol materialization revalidates the frozen hypothesis outcome, estimand, and expected sign.
- Safety ADD/REMOVE each have exactly four valid arms; task/presentation protocols never borrow a
  generic security arm.
- Every protocol freezes complete estimand definitions and their digest before variants/randomization;
  M6 cannot redefine treatment, control, outcome, sign, priority, or multiplicity family.
- `AllowedDelta` is an upper bound; missing target change is diagnostic, undeclared drift is hard
  invalidity.
- Matched controls pass a byte-recomputed canonical edit-footprint tolerance before assignment.
- Every arm is independently extracted with the run-locked blind extractor before randomization.
- All arms in one exact block freeze or the block receives no assignment.
- ADD/REMOVE, TargetSpecs, and arm protocols never share blocks.
- The default 12 seed slots balance every active 2/3/4-arm protocol.
- Assignment precedes generation and every assignment receives one execution record.
- Generated code enters only generation and the independent Oracle; no Code TSG or mechanism trace is
  introduced.
