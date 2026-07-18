# M6 Clustered ITT, JCI, RFCI, and Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Estimate task-clustered randomized ITT effects, run separate raw/JCI-constrained FCI analyses, expose optional py-tetrad RFCI sensitivity, complete synthetic SCM gates, and publish provenance-complete reports without code-mechanism artifacts.

**Architecture:** Exact assignment/outcome joins first produce one outcome row per committed assignment. Primary effects use only assigned arms and task-cluster resampling; JCI is a downstream structural analysis using the same rows plus one categorical arm context, while RFCI remains an isolated optional backend. Reports consume committed effect/PAG/failure artifacts and cannot feed back into hypotheses, variants, assignments, or effects.

**Tech Stack:** Python 3.12, Pydantic 2, NumPy/Pandas, causal-learn 0.1.4.7, existing deterministic RNG, optional py-tetrad commit `a30707264aa4363a23ac5f136a70bbdd62212f07`, optional JPype1 1.7.1/JDK 21+, pytest, Ruff.

---

## File responsibility map

- `src/secaware/schema/outcomes.py`: assignment outcome, functional outcome, contrast, ITT, JCI delta, RFCI capability, and analysis failure records.
- `src/secaware/outcomes/assembler.py`: exact assignment/execution/Oracle/diagnostic joins and conservative encoding.
- `src/secaware/outcomes/functional.py`: strict independent functional-outcome import/contract validation.
- `src/secaware/analysis/contrasts.py`: exact validation/flattening of M5-frozen contrast definitions.
- `src/secaware/analysis/itt.py`: arm means and risk/success differences.
- `src/secaware/analysis/cluster_bootstrap.py`: task-cluster confidence intervals and sensitivity bounds.
- `src/secaware/analysis/multiplicity.py`: pre-registered Bonferroni family adjustment.
- `src/secaware/causal/jci.py`: exact JCI strata, categorical context table, base/JCI BK, orientation delta.
- `src/secaware/discovery/rfci_backend.py`: optional py-tetrad capability and RFCI adapter.
- `src/secaware/pipeline/stages/effects.py`: assignment outcome plus ITT transaction.
- `src/secaware/pipeline/stages/jci.py`: raw/constrained PAG transaction.
- `src/secaware/pipeline/stages/rfci.py`: optional sensitivity transaction.
- `src/secaware/pipeline/stages/reporting.py`: final read-only reports.
- `src/secaware/reports/hypothesis_cards.py`: Prompt-hypothesis cards, never code mechanisms.
- `src/secaware/cli.py`: `confirm`, `analyze-jci`, `analyze-rfci`, `report`, and completed `run-all`.

### Task 1: Add exact assignment outcomes and independent functional outcome contracts

**Files:**
- Create: `src/secaware/schema/outcomes.py`
- Modify: `src/secaware/schema/oracle.py`
- Modify: `src/secaware/schema/__init__.py`
- Create: `src/secaware/outcomes/__init__.py`
- Create: `src/secaware/outcomes/assembler.py`
- Create: `src/secaware/outcomes/functional.py`
- Create: `src/secaware/pipeline/stages/functional_outcomes.py`
- Create: `tests/test_assignment_outcome_schema.py`
- Create: `tests/test_assignment_outcome_assembly.py`
- Create: `tests/test_functional_outcome_contract.py`
- Create: `tests/test_functional_outcome_import_stage.py`
- Modify: `tests/test_oracle_schema_v1.py`

- [ ] **Step 1: Write failing exact-outcome and missing-producer tests**

```python
def test_every_assignment_receives_one_primary_outcome() -> None:
    outcomes = assemble_assignment_outcomes(
        _assignments(),
        _executions_with_terminal_failure(),
        _oracles_for_generated_only(),
        _deltas(),
        functional_outcomes=(),
    )
    assert {item.assignment_id for item in outcomes} == {item.assignment_id for item in _assignments()}
    terminal = next(item for item in outcomes if item.execution_status == "terminal_no_code")
    assert terminal.secure_functional_success == 0
    assert terminal.oracle_evaluability == "not_required_no_code"


def test_missing_oracle_for_generated_assignment_is_not_encoded_as_zero() -> None:
    with pytest.raises(SecAwareError):
        assemble_assignment_outcomes(
            _assignments(),
            _generated_executions(),
            _oracles_with_one_missing(),
            _deltas(),
            functional_outcomes=(),
        )
```

Cover duplicate/extra assignment, execution, Oracle, delta, and functional rows; assignment/arm/task/
model/seed/semantic-target/target-instance/semantic-protocol/protocol-instance drift; generated versus terminal coverage; parse failure; functional
failure; secure/insecure/unknown; unknown primary zero without relabeling; missing/corrupt producers;
diagnostic target false/unknown; functional record policy mismatch; task effect without a functional
record; outcome mutation; raw prompt/code/finding text absence; and safe repr/errors.

- [ ] **Step 2: Run outcome tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_assignment_outcome_schema.py tests/test_assignment_outcome_assembly.py tests/test_functional_outcome_contract.py tests/test_functional_outcome_import_stage.py tests/test_oracle_schema_v1.py
```

Expected: FAIL because assignment-outcome schemas and the exact assembler do not exist.

- [ ] **Step 3: Implement strict persisted outcome records**

```python
class CWESecurityOutcome(str, Enum):
    SECURE = "secure"
    INSECURE = "insecure"
    UNKNOWN = "unknown"


class AssignmentEvaluability(str, Enum):
    EVALUABLE = "evaluable"
    UNKNOWN_PARSE_FAILURE = "unknown_parse_failure"
    NOT_REQUIRED_NO_CODE = "not_required_no_code"


class AssignmentOutcomeRecord(VersionedModel):
    schema_version: Literal["1.0"]
    outcome_id: str = Field(pattern=r"^assignment_outcome_[0-9a-f]{64}$")
    assignment_id: str
    task_id: str
    hypothesis_id: str
    target_spec_id: str
    target_instance_id: str
    arm_protocol_id: str
    protocol_instance_id: str
    variant_id: str
    arm_role: ArmRole
    model_id: str
    seed_id: int
    execution_status: AssignmentExecutionStatus
    secure_functional_success: Literal[0, 1]
    cwe_security_outcome: CWESecurityOutcome
    oracle_evaluability: AssignmentEvaluability
    parse_ok: bool
    functional_ok: bool
    target_changed: bool | None
    semantic_compliance: bool | None
    source_digests_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class FunctionalOutcomeRecord(VersionedModel):
    schema_version: Literal["1.0"]
    functional_outcome_id: str = Field(pattern=r"^functional_outcome_[0-9a-f]{64}$")
    assignment_id: str
    contract_id: str = Field(pattern=r"^functional_contract_[0-9a-f]{64}$")
    evaluator_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["pass", "fail", "unknown"]
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
```

Retain and revalidate M4B's `OracleEvaluability` contract: UNKNOWN is legal only for the completed
parse-failure case, while missing analyzers, analyzer execution errors, and invalid output remain hard
failures. `AssignmentEvaluability` adds only `NOT_REQUIRED_NO_CODE` for a committed terminal
generation result that intentionally has no Oracle row.

- [ ] **Step 4: Implement exact assembly and functional import validation**

```python
def primary_success(
    execution: AssignmentExecutionRecord,
    oracle: OracleRecord | None,
) -> int:
    if execution.status is AssignmentExecutionStatus.TERMINAL_NO_CODE:
        if oracle is not None:
            raise outcome_contract_error("terminal assignment has an Oracle row")
        return 0
    if oracle is None:
        raise outcome_contract_error("generated assignment is missing its Oracle row")
    return int(
        oracle.parse_ok
        and oracle.functional_ok
        and oracle.security_label is SecurityLabel.SECURE
    )
```

Snapshot and index each producer independently, require exact coordinates, then emit rows sorted by
assignment ID. Diagnostics are copied for reporting only and never affect row inclusion or the binary
outcome. `import_functional_outcomes` validates the pre-registered contract and exact assignment
coverage for task protocols; it never derives task success from prompt text or security findings.
The `import-functional-outcomes --results <path>` stage copies a validated external result artifact
into `analysis/functional_outcomes.jsonl` under a transaction, binds the external file hash in its
stage inputs, and requires exact contract/assignment coverage before commit.

- [ ] **Step 5: Re-run outcome/Oracle tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_assignment_outcome_schema.py tests/test_assignment_outcome_assembly.py tests/test_functional_outcome_contract.py tests/test_functional_outcome_import_stage.py tests/test_oracle_schema_v1.py tests/test_confirmation_oracle.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/schema/outcomes.py src/secaware/schema/oracle.py src/secaware/schema/__init__.py src/secaware/outcomes src/secaware/pipeline/stages/functional_outcomes.py tests/test_assignment_outcome_schema.py tests/test_assignment_outcome_assembly.py tests/test_functional_outcome_contract.py tests/test_functional_outcome_import_stage.py tests/test_oracle_schema_v1.py
git commit -m "feat: assemble exact randomized assignment outcomes"
```

### Task 2: Estimate pre-registered task-clustered ITT effects and sensitivity bounds

**Files:**
- Create: `src/secaware/analysis/contrasts.py`
- Create: `src/secaware/analysis/itt.py`
- Create: `src/secaware/analysis/cluster_bootstrap.py`
- Replace: `src/secaware/analysis/multiple_testing.py`
- Modify: `src/secaware/analysis/__init__.py`
- Modify: `src/secaware/schema/outcomes.py`
- Modify: `src/secaware/config.py`
- Create: `tests/test_preregistered_contrasts.py`
- Create: `tests/test_clustered_itt.py`
- Create: `tests/test_itt_sensitivity_bounds.py`
- Create: `tests/test_itt_diagnostic_invariance.py`

- [ ] **Step 1: Write failing hand-calculated ITT and invariance tests**

```python
def test_safety_add_primary_itt_matches_hand_calculation() -> None:
    effects = estimate_itt(_four_arm_hand_fixture(), _analysis_config())
    primary = next(
        item
        for item in effects
        if item.contrast_id == "safety_add.target_minus_noop.y_secure_functional"
    )
    assert primary.treatment_n == 4
    assert primary.control_n == 4
    assert primary.risk_difference == pytest.approx((3 / 4) - (1 / 4))


def test_target_and_semantic_diagnostics_cannot_change_itt() -> None:
    baseline = estimate_itt(_outcomes(), _analysis_config())
    mutated = estimate_itt(_outcomes_with_flipped_diagnostics(), _analysis_config())
    assert baseline == mutated


def test_itt_pools_task_instances_under_one_semantic_protocol() -> None:
    effects = estimate_itt(_same_protocol_many_task_instances(), _analysis_config())
    primary = _primary_effect(effects)
    assert primary.independent_task_n >= 20
    assert primary.target_spec_id == _semantic_target_spec_id()
    assert primary.arm_protocol_id == _semantic_arm_protocol_id()
```

Cover all safety ADD/REMOVE contrasts, family-valid task/presentation contrasts, arbitrary contrast
rejection, exact field-for-field equality between protocol nested contrasts and materialized records,
uniqueness by `(arm_protocol_id, contrast_id)`,
protocol outcome-variable mismatch, exact assignment denominator, duplicated task rows, task-cluster versus row-wise bootstrap,
deterministic draw order, minimum independent tasks, percentile interpolation, failed-replicate
handling, Bonferroni family adjustment, secure unknown conservative zero, best/worst bounds, terminal
failure, empty arm, opposite direction, presentation no-mechanism status, task missing functional
outcome, and mutation sensitivity.

- [ ] **Step 2: Run ITT tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_preregistered_contrasts.py tests/test_clustered_itt.py tests/test_itt_sensitivity_bounds.py tests/test_itt_diagnostic_invariance.py
```

Expected: FAIL because randomized ITT implementation does not exist.

- [ ] **Step 3: Validate and flatten the contrast definitions frozen by M5**

```python
class ContrastSpecRecord(VersionedModel):
    schema_version: Literal["1.0"]
    contrast_id: str
    arm_contrast_id: str
    arm_protocol_id: str
    treatment_arm: ArmRole
    control_arm: ArmRole
    source_outcome_variable_id: str
    outcome_id: str
    priority: Literal["primary", "secondary", "diagnostic"]
    expected_sign: Literal["positive", "negative", "null", "two_sided"]
    multiplicity_family_id: str
```

For each committed `ConfirmationProtocolRecord`, revalidate its content-derived
`contrast_set_sha256` and `arm_protocol_id`, then copy every nested `PreRegisteredContrastSpec`
field-for-field into `ContrastSpecRecord`. The uniqueness key is exactly
`(arm_protocol_id, contrast_id)`. Require exact equality in count, order, IDs, treatment/control,
outcome, priority, sign, and multiplicity family; M6 contains no arm-pair catalog and never enumerates
post-outcome combinations.

Implement only the outcome value projections named by the frozen specs. `y_cwe_secure`,
`y_cwe_insecure`, and `y_cwe_unknown` are three jointly reported indicators derived from the unchanged
categorical `CWESecurityOutcome`; `UNKNOWN` is never folded into either observed security label. Task
functional values come only from the independently committed contract-bound record.

- [ ] **Step 4: Implement point estimates, task-cluster bootstrap, and bounds**

```python
def risk_difference(
    rows: Sequence[AssignmentOutcomeRecord],
    treatment: ArmRole,
    control: ArmRole,
    value: Callable[[AssignmentOutcomeRecord], int],
) -> tuple[float, int, int]:
    treated = [value(row) for row in rows if row.arm_role is treatment]
    controls = [value(row) for row in rows if row.arm_role is control]
    if not treated or not controls:
        raise insufficient_contrast_error()
    return (sum(treated) / len(treated)) - (sum(controls) / len(controls)), len(treated), len(controls)
```

Cluster by `task_id`: each bootstrap replicate samples sorted task IDs with replacement and includes
all assignments belonging to each sampled occurrence. Use the M4B deterministic RNG. Predeclare
`bootstrap_samples`, percentile method `linear-v1`, maximum failed fraction, confidence level, and
`multiplicity_method="bonferroni"`. Family-adjusted percentile tails use
`alpha / number_of_pre_registered_contrasts`.

Form effect groups by semantic
`(hypothesis_id, target_spec_id, arm_protocol_id, model_id, contrast_id, outcome_id)`, never by
`target_instance_id` or `protocol_instance_id`. Require multiple independent task IDs and exactly one
valid instance pair per task/semantic protocol; hash the complete sorted instance universe into every
effect record.

For valid Oracle unknown, primary uses zero. Best bound sets unknown treatment rows to one and unknown
control rows to zero; worst bound reverses those choices. Never relabel the CWE category.

- [ ] **Step 5: Persist effect records and statuses**

```python
class ITTEffectRecord(VersionedModel):
    schema_version: Literal["1.0"]
    effect_id: str = Field(pattern=r"^itt_effect_[0-9a-f]{64}$")
    hypothesis_id: str
    target_spec_id: str
    arm_protocol_id: str
    model_id: str
    contrast_id: str
    outcome_id: str
    treatment_n: int
    control_n: int
    independent_task_n: int
    risk_difference: float
    ci_low: float
    ci_high: float
    sensitivity_low: float
    sensitivity_high: float
    status: str
    assignment_universe_sha256: str
    target_instance_universe_sha256: str
    bootstrap_manifest_sha256: str
```

Safety status may reflect expected-direction confirmation. Presentation status is limited to
`negative_control_consistent`, `negative_control_shift`, or `unsupported`; it can never be a
confirmed safety mechanism. Task status is `unsupported_missing_functional_outcome` unless exact
functional records exist.

- [ ] **Step 6: Re-run ITT tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_preregistered_contrasts.py tests/test_clustered_itt.py tests/test_itt_sensitivity_bounds.py tests/test_itt_diagnostic_invariance.py
```

Expected: PASS.

- [ ] **Step 7: Commit**

```powershell
git add src/secaware/analysis src/secaware/schema/outcomes.py src/secaware/config.py tests/test_preregistered_contrasts.py tests/test_clustered_itt.py tests/test_itt_sensitivity_bounds.py tests/test_itt_diagnostic_invariance.py
git commit -m "feat: estimate task-clustered randomized itt"
```

### Task 3: Assemble exact JCI strata, categorical context, and separate base/JCI knowledge

**Files:**
- Create: `src/secaware/causal/jci.py`
- Modify: `src/secaware/schema/causal.py`
- Modify: `src/secaware/schema/outcomes.py`
- Create: `tests/test_jci_table_builder.py`
- Create: `tests/test_jci_background_knowledge.py`
- Create: `tests/test_jci_provenance_boundary.py`

- [ ] **Step 1: Write failing stratum/context/BK separation tests**

```python
def test_jci_tables_never_pool_target_or_protocol_semantics() -> None:
    tables, rows = build_jci_tables(_assignments(), _outcomes(), _variant_graphs())
    assert all(len({row.target_spec_id for row in _rows_for(table, rows)}) == 1 for table in tables)
    assert all(len({row.arm_protocol_id for row in _rows_for(table, rows)}) == 1 for table in tables)
    assert all(len({row.task_id for row in _rows_for(table, rows)}) >= 20 for table in tables)
    assert all(len({row.target_instance_id for row in _rows_for(table, rows)}) >= 20 for table in tables)
    assert all(len({row.protocol_instance_id for row in _rows_for(table, rows)}) >= 20 for table in tables)


def test_raw_background_has_no_context_incident_prohibition() -> None:
    base, jci = build_jci_background(_jci_table())
    assert base.unconstrained_variable_ids == ("c.arm",)
    assert all("c.arm" not in pair for pair in base.forbidden_directions)
    assert all("c.arm" not in pair for pair in base.forbidden_adjacencies)
    backend = to_causal_learn_background(base)
    assert all(
        not backend.is_forbidden(GraphNode(system_id), GraphNode("c.arm"))
        and not backend.is_forbidden(GraphNode("c.arm"), GraphNode(system_id))
        for system_id in _system_variable_ids()
    )
    assert all(
        (source, target) in jci.materialized_background_knowledge.forbidden_directions
        for source, target in _system_to_context_pairs()
    )


def test_executor_and_extractor_coordinates_are_provenance_not_causal_columns() -> None:
    table = build_jci_tables(_assignments(), _outcomes(), _variant_graphs())[0][0]
    forbidden = {
        "intervention_mode",
        "intervention_executor_kind",
        "executor_policy_sha256",
        "extractor_backend",
        "extractor_policy_sha256",
        "target_instance_id",
        "protocol_instance_id",
    }
    assert forbidden.isdisjoint({variable.variable_id for variable in table.variables})
```

Cover exact semantic stratum `(scope, model, hypothesis, target, protocol)`, cross-task instance
pooling, ADD/REMOVE separation, three/four
arm separation, feature-family separation, one categorical context column, one-hot rejection,
category order, identical row set for raw/constrained runs, outcome/extractor diagnostic leakage,
executor/extractor policy or mode as a causal column, code/finding text imports, missing variant TSG,
assignment/outcome mismatch, insufficient support,
no required context adjacency, assumption ID/digest mutation, and raw C freedom.

- [ ] **Step 2: Run JCI table/BK tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_jci_table_builder.py tests/test_jci_background_knowledge.py tests/test_jci_provenance_boundary.py
```

Expected: FAIL because JCI assembly does not exist.

- [ ] **Step 3: Implement exact JCI stratum and categorical context records**

```python
class JCIStratum(StrictModel):
    scope_id: str
    model_id: str
    hypothesis_id: str
    target_spec_id: str
    arm_protocol_id: str


class JCIContextSpec(StrictModel):
    variable_id: Literal["c.arm"] = "c.arm"
    arm_roles: tuple[ArmRole, ...]
    category_codes: tuple[int, ...]


class JCIObservationRecord(VersionedModel):
    schema_version: Literal["1.0"]
    table_id: str
    row_id: str
    assignment_id: str
    task_id: str
    target_spec_id: str
    target_instance_id: str
    arm_protocol_id: str
    protocol_instance_id: str
    values: tuple[int, ...]


class JCIBackgroundKnowledgeRecord(VersionedModel):
    schema_version: Literal["1.0"]
    knowledge_id: str = Field(pattern=r"^jci_bk_[0-9a-f]{64}$")
    base_background_knowledge_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assumption_ids: tuple[str, ...]
    added_forbidden_directions: tuple[tuple[str, str], ...]
    required_directions: tuple[tuple[str, str], ...] = ()
    materialized_background_knowledge: BackgroundKnowledgeRecord
    knowledge_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def jci_stratum_key(assignment: AssignmentRecord, hypothesis: FrozenHypothesisRecord) -> JCIStratum:
    return JCIStratum(
        scope_id=hypothesis.scope_id,
        model_id=assignment.experimental_unit.model_id,
        hypothesis_id=assignment.experimental_unit.hypothesis_id,
        target_spec_id=assignment.target_spec_id,
        arm_protocol_id=assignment.arm_protocol_id,
    )
```

Build `X` from realized frozen variant Prompt TSG feature queries, `Y` from
`AssignmentOutcomeRecord`, and `C` from assigned `arm_role`. Do not include `target_changed`, semantic
compliance, execution status, code, finding text, model ID, intervention mode/executor, or extractor
backend/policy as columns. Those remain run/protocol provenance only. Sort arm roles by the exact
protocol order and encode one categorical integer column.
Build one table across all eligible task-specific instances sharing the semantic `JCIStratum`; never
include either instance ID as a matrix column. Require the configured independent-task minimum and
exactly one protocol instance per task/semantic target before running FCI.

- [ ] **Step 4: Implement base and JCI assumption artifacts**

```python
JCI_CONTEXT_EXOGENEITY = "jci.randomized_context_exogeneity.v1"


def build_jci_background(
    table: CausalTableRecord,
) -> tuple[BackgroundKnowledgeRecord, JCIBackgroundKnowledgeRecord]:
    base = build_base_knowledge_ignoring_context_incidence(table)
    system_ids = tuple(item.variable_id for item in table.variables if item.role is not VariableRole.C)
    additions = tuple((variable_id, "c.arm") for variable_id in system_ids)
    provenance = JCIBackgroundKnowledgeRecord.from_base(
        base,
        assumption_ids=(JCI_CONTEXT_EXOGENEITY,),
        added_forbidden_directions=additions,
        required_directions=(),
    )
    return base, provenance
```

The raw run applies base `W/X/Y` restrictions only and leaves every `C`-incident direction and
adjacency unmentioned. It puts `c.arm` in `unconstrained_variable_ids` and does not materialize its
nominal `CausalVariableSpec.temporal_tier` into causal-learn. The constrained run retains that omitted
tier and adds only the explicit system-to-context prohibitions. Persist the exact sorted assumption ID
set and digest, and test the converted causal-learn BK—not only the record fields—in both directions
for every context/system pair.

- [ ] **Step 5: Re-run JCI table/BK/provenance tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_jci_table_builder.py tests/test_jci_background_knowledge.py tests/test_jci_provenance_boundary.py tests/test_causal_background_knowledge.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/causal/jci.py src/secaware/schema/causal.py src/secaware/schema/outcomes.py tests/test_jci_table_builder.py tests/test_jci_background_knowledge.py tests/test_jci_provenance_boundary.py
git commit -m "feat: assemble jci context tables and knowledge"
```

### Task 4: Run raw and JCI-constrained FCI and preserve assumption-set orientation deltas

**Files:**
- Modify: `src/secaware/causal/jci.py`
- Modify: `src/secaware/schema/outcomes.py`
- Create: `tests/test_jci_fci_analysis.py`
- Create: `tests/test_jci_orientation_delta.py`
- Create: `tests/test_jci_effect_isolation.py`

- [ ] **Step 1: Write failing raw/constrained/delta/isolation tests**

```python
def test_raw_and_constrained_runs_use_identical_data_and_distinct_bk() -> None:
    result = analyze_jci_stratum(_jci_table(), _rows(), _config(), runner=_capturing_runner())
    assert result.raw_pag.run_kind is PAGRunKind.JCI_RAW
    assert result.constrained_pag.run_kind is PAGRunKind.JCI_CONSTRAINED
    assert result.raw_pag.table_id == result.constrained_pag.table_id
    assert result.raw_pag.background_knowledge_sha256 != result.constrained_pag.background_knowledge_sha256


def test_orientation_delta_records_whole_assumption_set_not_single_cause() -> None:
    delta = compare_jci_pags(_raw_pag(), _constrained_pag(), _jci_knowledge())
    assert delta.assumption_ids == _jci_knowledge().assumption_ids
    assert delta.per_assumption_attribution is False
```

Add tests for edge added/removed/mark changed, no-change delta, canonical endpoint order, circle
preservation, assumption digest, raw C freedom, constrained BK final validation, same matrix/config,
FCI timeout/failure, deterministic rerun, JCI result unable to alter frozen hypotheses, assignment,
contrast, effect point/CI/status, or report primary effect fields.

- [ ] **Step 2: Run JCI analysis tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_jci_fci_analysis.py tests/test_jci_orientation_delta.py tests/test_jci_effect_isolation.py
```

Expected: FAIL because JCI FCI analysis and delta records are absent.

- [ ] **Step 3: Implement paired FCI runs through the existing adapter**

```python
def analyze_jci_stratum(
    table: CausalTableRecord,
    rows: Sequence[CausalObservationRecord],
    config: FCIDiscoveryConfig,
    runner: FCIRunner,
) -> JCIAnalysisResult:
    matrix = matrix_for_exact_rows(table, rows)
    base, provenance = build_jci_background(table)
    constrained = provenance.materialized_background_knowledge
    raw_pag = runner.run(matrix, table, base, config, PAGRunKind.JCI_RAW)
    constrained_pag = runner.run(matrix, table, constrained, config, PAGRunKind.JCI_CONSTRAINED)
    delta = compare_jci_pags(raw_pag, constrained_pag, provenance)
    return JCIAnalysisResult(raw_pag=raw_pag, constrained_pag=constrained_pag, delta=delta)
```

Define the in-memory result container in the same module:

```python
@dataclass(frozen=True, slots=True)
class JCIAnalysisResult:
    raw_pag: PAGRecord
    constrained_pag: PAGRecord
    delta: JCIOrientationDeltaRecord
```

Both runs receive identical matrix bytes, variable order, alpha/depth/path limits, and backend
version. Validate raw PAG against base BK and constrained PAG against the full JCI BK.

- [ ] **Step 4: Implement complete assumption-set deltas**

```python
class EndpointChangeRecord(StrictModel):
    left: str
    right: str
    raw_left_mark: EndpointMark | None
    raw_right_mark: EndpointMark | None
    constrained_left_mark: EndpointMark | None
    constrained_right_mark: EndpointMark | None
    change_kind: Literal["edge_added", "edge_removed", "marks_changed"]


class JCIOrientationDeltaRecord(VersionedModel):
    schema_version: Literal["1.0"]
    delta_id: str = Field(pattern=r"^jci_delta_[0-9a-f]{64}$")
    raw_pag_id: str
    constrained_pag_id: str
    assumption_ids: tuple[str, ...]
    assumption_set_sha256: str
    per_assumption_attribution: Literal[False] = False
    changes: tuple[EndpointChangeRecord, ...]
```

Diff the union of canonical edge pairs and attach the entire enabled assumption set to every delta
record. Do not label a particular assumption as the cause of an endpoint change and do not implement
assumption ablation.

- [ ] **Step 5: Re-run JCI analysis/isolation tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_jci_fci_analysis.py tests/test_jci_orientation_delta.py tests/test_jci_effect_isolation.py tests/test_causal_learn_fci_backend.py
```

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/causal/jci.py src/secaware/schema/outcomes.py tests/test_jci_fci_analysis.py tests/test_jci_orientation_delta.py tests/test_jci_effect_isolation.py
git commit -m "feat: preserve raw and constrained jci pags"
```

### Task 5: Add optional py-tetrad RFCI sensitivity behind a Java capability gate

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/secaware/config.py`
- Create: `src/secaware/discovery/rfci_backend.py`
- Modify: `src/secaware/schema/outcomes.py`
- Create: `tests/test_rfci_capability.py`
- Create: `tests/test_rfci_adapter.py`
- Modify: `tests/test_packaging.py`

- [ ] **Step 1: Write failing absent/present capability and adapter tests**

```python
def test_missing_rfci_dependencies_are_nonfatal_to_minimum_backend(monkeypatch) -> None:
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    capability = detect_rfci_capability()
    assert capability.available is False
    assert capability.requires_java is True
    assert capability.status == "unavailable"


def test_rfci_adapter_uses_gsquare_and_never_sets_required_edges(fake_tetrad_search) -> None:
    pag = run_rfci_sensitivity(_table(), _rows(), _knowledge(), _rfci_config(), fake_tetrad_search)
    assert fake_tetrad_search.used_g_square is True
    assert fake_tetrad_search.required_edges == []
    assert pag.run_kind is PAGRunKind.RFCI_SENSITIVITY
```

Cover disabled, missing JPype, missing py-tetrad, missing/old Java, wrong py-tetrad commit/JAR hash,
Python 3.12 runtime behavior and RFCI capability, BK tiers/forbidden pairs, required-edge absence,
PAG codec, timeout/child crash, sensitivity-only status, config drift, and no import/startup of JPype
when RFCI is disabled.

- [ ] **Step 2: Add the optional dependency declaration and verify RED**

```toml
[project.optional-dependencies]
rfci = [
  "JPype1==1.7.1; python_version >= '3.12'",
  "py-tetrad @ git+https://github.com/cmu-phil/py-tetrad.git@a30707264aa4363a23ac5f136a70bbdd62212f07 ; python_version >= '3.12'",
]
```

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_rfci_capability.py tests/test_rfci_adapter.py tests/test_packaging.py
```

Expected: FAIL because RFCI capability/adapter code does not exist. Do not install the optional extra
in the minimum environment.

- [ ] **Step 3: Implement explicit optional configuration and capability records**

```python
class RFCIConfig(StrictModel):
    enabled: bool = False
    py_tetrad_commit: Literal["a30707264aa4363a23ac5f136a70bbdd62212f07"] = "a30707264aa4363a23ac5f136a70bbdd62212f07"
    jpype_version: Literal["1.7.1"] = "1.7.1"
    minimum_java_major: Literal[21] = 21
    alpha: float = Field(default=0.05, gt=0.0, lt=1.0, allow_inf_nan=False)
    depth: int = Field(default=3, ge=0, le=8)
    max_discriminating_path_length: int = Field(default=6, ge=1, le=16)
    timeout_seconds: float = Field(default=180.0, gt=0.0, le=3600.0)


class RFCICapabilityRecord(VersionedModel):
    schema_version: Literal["1.0"]
    available: bool
    status: Literal["disabled", "available", "unavailable"]
    requires_java: Literal[True] = True
    python_version: str
    java_major: int | None
    jpype_version: str | None
    py_tetrad_commit: str | None
    tetrad_jar_sha256: str | None
    reason_code: str | None
```

Detection returns a record and never raises when disabled or unavailable. Import JPype/py-tetrad only
inside the spawned RFCI worker after capability validation.

- [ ] **Step 4: Implement the py-tetrad adapter in an isolated worker**

The worker executes:

```python
search = TetradSearch(pd.DataFrame(matrix, columns=variable_ids))
search.use_g_square(alpha=config.alpha)
for variable_id, tier in knowledge.tiers:
    search.add_to_tier(tier, variable_id)
for source, target in expanded_forbidden_directions(knowledge):
    search.set_forbidden(source, target)
search.run_rfci(
    depth=config.depth,
    stable_fas=True,
    max_disc_path_length=config.max_discriminating_path_length,
    complete_rule_set_used=True,
)
backend_graph = search.get_causal_learn()
```

Convert through the shared PAG codec and validate against BK. Run only as a sensitivity artifact;
never replace primary FCI or ITT. If capability is unavailable, persist the capability record and no
PAG, then continue successfully.

- [ ] **Step 5: Re-run capability/adapter/packaging tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_rfci_capability.py tests/test_rfci_adapter.py tests/test_packaging.py tests/test_causal_learn_fci_backend.py
```

Expected: PASS in the no-Java minimum environment; adapter tests use a fake py-tetrad boundary.

- [ ] **Step 6: Commit**

```powershell
git add pyproject.toml src/secaware/config.py src/secaware/discovery/rfci_backend.py src/secaware/schema/outcomes.py tests/test_rfci_capability.py tests/test_rfci_adapter.py tests/test_packaging.py
git commit -m "feat: add optional rfci sensitivity backend"
```

### Task 6: Complete synthetic SCM gates including deterministic JCI context

**Files:**
- Modify: `tests/synthetic/scm_fixtures.py`
- Modify: `tests/test_synthetic_fci_scm.py`
- Create: `tests/test_synthetic_jci_scm.py`
- Create: `tests/test_synthetic_rfci_sensitivity.py`

- [ ] **Step 1: Add a deterministic randomized-context SCM**

```python
def deterministic_context_scm(n_per_arm: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    context = np.repeat(np.arange(4, dtype=np.int64), n_per_arm)
    target_feature = (context == 0).astype(np.int64)
    noise = rng.binomial(1, 0.10, size=context.size)
    outcome = np.bitwise_xor(target_feature, noise)
    return pd.DataFrame(
        {
            "c.arm": context,
            "x.target_feature": target_feature,
            "y.secure_functional": outcome,
        }
    )
```

The deterministic C→X relation intentionally creates sparse/zero cells. Register exact category
domains before constructing the matrix.

- [ ] **Step 2: Assert stable result or explicit fail-closed degeneracy**

Run raw and constrained JCI analysis twice. Accept exactly two outcomes:

1. both runs produce deterministic canonical PAG/delta artifacts satisfying their BK; or
2. both runs produce the same typed `DEGENERATE_GSQ_SUPPORT` failure with no partial PAG.

Do not require a unique orientation from deterministic data and do not catch an arbitrary exception
as acceptable.

- [ ] **Step 3: Re-run all four synthetic SCM families**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_synthetic_fci_scm.py tests/test_synthetic_jci_scm.py tests/test_synthetic_rfci_sensitivity.py
```

Expected: true chain, latent confounding, null factor, and deterministic-context gates pass. RFCI
real-backend cases skip only when the optional capability record is unavailable; fake-adapter cases
always run.

- [ ] **Step 4: Commit**

```powershell
git add tests/synthetic/scm_fixtures.py tests/test_synthetic_fci_scm.py tests/test_synthetic_jci_scm.py tests/test_synthetic_rfci_sensitivity.py
git commit -m "test: add randomized jci scm gates"
```

### Task 7: Publish effects/JCI/RFCI stages and replace legacy pair/mechanism reporting

**Files:**
- Create: `src/secaware/pipeline/stages/effects.py`
- Create: `src/secaware/pipeline/stages/jci.py`
- Create: `src/secaware/pipeline/stages/rfci.py`
- Create: `src/secaware/pipeline/stages/reporting.py`
- Modify: `src/secaware/pipeline/stages/__init__.py`
- Modify: `src/secaware/analysis/__init__.py`
- Modify: `src/secaware/discovery/__init__.py`
- Modify: `src/secaware/intervention/__init__.py`
- Modify: `src/secaware/schema/__init__.py`
- Replace: `src/secaware/reports/tables.py`
- Create: `src/secaware/reports/hypothesis_cards.py`
- Delete: `src/secaware/reports/mechanism_cards.py`
- Delete: `src/secaware/analysis/bootstrap.py`
- Delete: `src/secaware/analysis/effects.py`
- Delete: `src/secaware/analysis/pairing.py`
- Delete: `src/secaware/schema/results.py`
- Delete: `src/secaware/schema/interventions.py`
- Delete: `src/secaware/schema/hypotheses.py`
- Delete: `src/secaware/discovery/candidate_enum.py`
- Delete: `src/secaware/discovery/scoring.py`
- Delete: `src/secaware/discovery/stability.py`
- Delete: `src/secaware/discovery/tsg_qcd.py`
- Delete: `src/secaware/intervention/operators.py`
- Delete: `src/secaware/intervention/validator.py`
- Delete: `src/secaware/intervention/verbalizer.py`
- Delete: `src/secaware/intervention/patch.py`
- Create: `tests/test_effect_stage.py`
- Create: `tests/test_jci_stage.py`
- Create: `tests/test_rfci_stage.py`
- Replace: `tests/test_effects.py`
- Replace: `tests/test_intervention.py`
- Delete: `tests/test_discovery_graph_scoring.py`
- Delete: `tests/test_intervention_graph_validation.py`
- Create: `tests/test_prompt_only_reports.py`
- Modify: `tests/test_stage_orchestration.py`

- [ ] **Step 1: Write failing complete-artifact and one-way-dependency tests**

```python
def test_analysis_stages_publish_complete_artifacts(tmp_path) -> None:
    store = _run_through_confirmation_oracle(tmp_path)
    effects_stage(store.config, store, force=False)
    jci_stage(store.config, store, force=False, runner=_fake_fci_runner())
    rfci_stage(store.config, store, force=False, runner=_fake_rfci_runner())
    assert _analysis_names(store) >= {
        "assignment_outcomes.jsonl",
        "contrast_specs.jsonl",
        "itt_effects.jsonl",
        "effect_bootstrap_draws.jsonl",
        "effect_failures.jsonl",
        "jci_tables.jsonl",
        "jci_observations.jsonl",
        "jci_raw_pags.jsonl",
        "jci_background_knowledge.jsonl",
        "jci_constrained_pags.jsonl",
        "jci_orientation_deltas.jsonl",
        "jci_failures.jsonl",
        "rfci_capability.jsonl",
        "rfci_pags.jsonl",
        "rfci_failures.jsonl",
    }


def test_jci_artifacts_are_not_effect_stage_inputs() -> None:
    assert all("jci" not in path.name for path in EFFECT_STAGE_INPUTS)
```

Add exact producer holds, outcome/assignment/delta coverage, all-or-nothing output transactions,
force-run rollback, concurrent mutation, empty contrasts, JCI/RFCI failure records, report read-only
behavior, no mechanism-card filename/key, no legacy pair artifact, no code fields, and all deleted
legacy imports absent. Replace/remove every old test consumer before deleting its module; in particular,
the old discovery-scoring and intervention-graph-validation suites are superseded by M4B/M5 gates and
are deleted in this task, while generation/Oracle/Prompt-TSG consumers were migrated in M4A/M5.

- [ ] **Step 2: Run stage/report tests and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_effect_stage.py tests/test_jci_stage.py tests/test_rfci_stage.py tests/test_prompt_only_reports.py tests/test_stage_orchestration.py
```

Expected: FAIL because stages and new reports do not exist.

- [ ] **Step 3: Implement the effect stage**

Hold committed assignments, executions, confirmation Oracle, graph deltas, semantic targets/protocols,
their task-specific instances, frozen hypotheses, and optional functional outcomes. Publish assignment outcomes, contrast specs, clustered
draw manifests, effects, and typed failures in one transaction. JCI and RFCI paths are not inputs.

- [ ] **Step 4: Implement JCI and RFCI stages**

JCI holds effect-stage assignment outcomes plus assignments and variant Prompt TSGs, then publishes
all raw/constrained artifacts atomically. It may read ITT artifacts only to assert their digest remains
unchanged before/after JCI; it cannot rewrite them.

RFCI holds causal tables/BK and emits one capability record plus zero or more sensitivity PAGs and
failures. Its manifest/output set is valid when capability is unavailable.

- [ ] **Step 5: Replace reports and remove legacy pair/mechanism code**

`write_reports` consumes frozen hypotheses, Prompt variants/deltas, assignments, assignment outcomes,
ITT effects, PAGs, JCI deltas, RFCI capability, and typed failures. Emit:

```text
reports/discovery_pags.jsonl
reports/hypotheses.jsonl
reports/interventions.jsonl
reports/assignments.jsonl
reports/effects.csv
reports/jci_orientations.csv
reports/failures.csv
reports/hypothesis_cards.jsonl
reports/summary.md
```

Cards may say `prompt_path` or `hypothesis_path`; they must not say `code mechanism`, `mediator`,
`source-to-sink code path`, or claim a PAG circle is a directed cause. Delete all old pairing,
heuristic discovery, old schema, and `mechanism_cards` modules only after `rg` proves no live import.

- [ ] **Step 6: Re-run stage/report/full legacy-removal tests**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_effect_stage.py tests/test_jci_stage.py tests/test_rfci_stage.py tests/test_effects.py tests/test_intervention.py tests/test_prompt_only_reports.py tests/test_stage_orchestration.py
if (rg -n '\b(PairResult|EffectRecord|InterventionRecord|HypothesisRecord)\b|mechanism_cards|tsg_qcd' src tests) { throw 'legacy reference remains' }
```

Expected: pytest passes and `rg` returns no live source/test references.

- [ ] **Step 7: Commit**

```powershell
git add src/secaware/pipeline/stages src/secaware/reports src/secaware/analysis src/secaware/schema src/secaware/discovery src/secaware/intervention tests/test_effect_stage.py tests/test_jci_stage.py tests/test_rfci_stage.py tests/test_effects.py tests/test_intervention.py tests/test_discovery_graph_scoring.py tests/test_intervention_graph_validation.py tests/test_prompt_only_reports.py tests/test_stage_orchestration.py
git commit -m "feat: publish itt jci rfci and prompt reports"
```

### Task 8: Complete CLI/run-all, migrations, architecture gates, and final verification

**Files:**
- Modify: `src/secaware/io/run_store.py`
- Modify: `src/secaware/cli.py`
- Modify: `README.md`
- Create: `docs/migrations/prompt-only-fci-jci.md`
- Create: `tests/test_m6_architecture.py`
- Modify: `tests/test_run_all_demo.py`
- Modify: `tests/test_packaging.py`
- Modify: `tests/test_preflight.py`

- [ ] **Step 1: Write failing final CLI, run-all, and architecture gates**

```python
def test_final_tree_has_no_code_tsg_or_code_mechanism_artifact() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in Path("src/secaware").rglob("*.py"))
    forbidden = ("CodeTSG", "CodeMechanismTrace", "code_mechanism", "mechanism_cards")
    assert not any(token in source for token in forbidden)


def test_primary_itt_has_no_diagnostic_filter() -> None:
    tree = ast.parse(Path("src/secaware/analysis/itt.py").read_text(encoding="utf-8"))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    assert "target_changed" not in names
    assert "semantic_compliance" not in names


def test_minimum_import_does_not_start_java() -> None:
    completed = subprocess.run(
        [sys.executable, "-c", "import secaware; import secaware.cli; print('ok')"],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "JAVA_HOME": ""},
    )
    assert completed.stdout.strip() == "ok"


def test_final_cli_registers_analysis_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("import-functional-outcomes", "confirm", "analyze-jci", "analyze-rfci", "report"):
        assert command in result.stdout
```

Also assert discovery reads only discover split, confirmation only confirm split, model stratification,
one categorical JCI context, raw/JCI PAG separation, assumption-set provenance, optional RFCI,
complete artifacts, intervention executor/mode absent from causal-variable tables, no benchmark/ranking
code, and no Java dependency in the base dependency list.

- [ ] **Step 2: Run the new final integration gates and verify RED**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_m6_architecture.py tests/test_run_all_demo.py tests/test_packaging.py tests/test_preflight.py
```

Expected: FAIL because the final commands/run order and architecture surface are incomplete.

- [ ] **Step 3: Register final commands, complete `run-all`, and document the boundary**

Expose `import-functional-outcomes`, `confirm`, `analyze-jci`, `analyze-rfci`, and `report`. `confirm`
runs outcome assembly and primary ITT only. `analyze-jci` and `analyze-rfci` are explicit secondary
stages. Final `run-all` order is M4A extraction → observed generation/Oracle → M4B tables/FCI/freeze →
M5 variants/randomization/generation/Oracle → M6 confirm → JCI → optional RFCI → report. When a task
protocol declares a functional contract, `run-all` requires an already committed
`import-functional-outcomes` artifact before `confirm`; it never fabricates or derives that result.
Add new directories and seal-required stages to RunStore.

Document:

- Prompt TSG graph edges are semantic/program-requirement structure, not causal arrows;
- PAG endpoints are learned uncertainty and circles remain circles;
- randomized ITT is the primary causal estimate;
- JCI is secondary and cannot modify ITT or hypotheses;
- RFCI is optional Java sensitivity;
- generated code is evaluated by Oracle/functional evaluators only;
- unknown/non-evaluable primary encoding and best/worst bounds;
- pre-random exclusion versus post-assignment ITT;
- all stage artifact filenames, digests, and migration/regeneration instructions.

- [ ] **Step 4: Run the focused M6 suite**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_assignment_outcome_schema.py tests/test_assignment_outcome_assembly.py tests/test_functional_outcome_contract.py tests/test_preregistered_contrasts.py tests/test_clustered_itt.py tests/test_itt_sensitivity_bounds.py tests/test_itt_diagnostic_invariance.py tests/test_jci_table_builder.py tests/test_jci_background_knowledge.py tests/test_jci_provenance_boundary.py tests/test_jci_fci_analysis.py tests/test_jci_orientation_delta.py tests/test_jci_effect_isolation.py tests/test_rfci_capability.py tests/test_rfci_adapter.py tests/test_synthetic_fci_scm.py tests/test_synthetic_jci_scm.py tests/test_synthetic_rfci_sensitivity.py tests/test_effect_stage.py tests/test_jci_stage.py tests/test_rfci_stage.py tests/test_prompt_only_reports.py tests/test_m6_architecture.py
```

Expected: PASS in the minimum no-Java environment; only explicit real-RFCI capability tests skip.

- [ ] **Step 5: Run the complete minimum matrix**

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format --check src tests
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m secaware --help
.\.venv\Scripts\python.exe -m secaware confirm --help
.\.venv\Scripts\python.exe -m secaware analyze-jci --help
.\.venv\Scripts\python.exe -m secaware analyze-rfci --help
git diff --check
if (Test-Path uv.lock) { throw 'uv.lock must not exist' }
```

Expected: every command exits zero; the base environment imports and tests without Java.

- [ ] **Step 6: Run Python-version and optional capability matrices**

On the Python 3.12 minimum environment:

```powershell
uv run --no-project --python 3.12 --with-editable ".[dev,api]" pytest -q
```

On a separate Python 3.12 + JDK 21 environment:

```powershell
uv run --no-project --python 3.12 --with-editable ".[dev,api,rfci]" pytest -q -m rfci_real
```

Expected: minimum matrices pass without RFCI; optional matrix passes the exact real-adapter gate.
An environment lacking JDK 21 does not run the optional command; its normal pipeline behavior is
covered by the unavailable-capability test and cannot change minimum results.

- [ ] **Step 7: Commit final docs and gates**

```powershell
git add src/secaware/io/run_store.py src/secaware/cli.py README.md docs/migrations/prompt-only-fci-jci.md tests/test_m6_architecture.py tests/test_run_all_demo.py tests/test_packaging.py tests/test_preflight.py
git commit -m "docs: complete prompt-only fci jci rollout"
```

## M6 self-review checklist

- Every committed assignment has exactly one primary outcome row and remains in ITT.
- Missing/corrupt producers abort; valid terminal/unknown non-success is conservative zero.
- Effects are grouped by assigned arm and clustered by task, never filtered by diagnostics.
- Contrast records are exact flattenings of M5-frozen definitions, unique by protocol plus contrast ID.
- Task effects require independent `FunctionalOutcomeRecord`; presentation effects cannot receive a
  safety-mechanism status.
- JCI strata do not pool targets, operations, families, hypotheses, or arm protocols.
- Each semantic ITT/JCI group pools many independent task/protocol instances; instance IDs remain row
  provenance and never become strata or causal columns.
- Raw JCI BK omits the context tier and has no context-incidence restrictions even after backend
  conversion; constrained BK records exact assumption IDs and explicit system-to-context prohibitions.
- Orientation deltas attach the complete assumption set and make no single-assumption attribution.
- RFCI is optional, isolated, Java-gated, and never replaces primary FCI/ITT.
- Final artifacts and reports contain no Code TSG, code mechanism, or mediation claim.
