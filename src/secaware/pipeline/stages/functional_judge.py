"""Transactional blind functional evaluation of randomized generated programs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.functional_judge.factory import create_functional_judge
from secaware.functional_judge.judge import LLMFunctionalJudge
from secaware.functional_judge.schema import (
    FunctionalJudgePassRecord,
    ProgramFunctionalOutcomeRecord,
    TaskFunctionalContractRecord,
)
from secaware.functional_judge.validation import validate_program_functional_outcomes
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import sha256_path
from secaware.pipeline.jsonl_stage import JsonlOutputSpec, execute_jsonl_stage_transaction
from secaware.pipeline.stages.confirmation_generation import (
    CONFIRMATION_GENERATION_OUTPUTS,
    validate_confirmation_generation_bundle,
)
from secaware.pipeline.stages.prompt_variants import PROMPT_VARIANT_OUTPUTS
from secaware.pipeline.stages.randomization import RANDOMIZATION_OUTPUTS
from secaware.schema.experiments import (
    AssignmentExecutionRecord,
    AssignmentRecord,
    PromptVariantRecord,
    RandomizationManifestRecord,
)
from secaware.schema.generation import GenerationRequestRecord
from secaware.schema.records import CanonicalGeneratedCodeRecord, PromptRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256

_STAGE = "judge-functionality"
_MAX_RECORDS = 100_000
_MAX_LINE_CHARS = 4_000_000
_MAX_TOTAL_CHARS = 512_000_000
FUNCTIONAL_JUDGE_OUTPUTS = (
    ("functional_judge_passes.jsonl", FunctionalJudgePassRecord),
    ("program_functional_outcomes.jsonl", ProgramFunctionalOutcomeRecord),
)


@dataclass(frozen=True, slots=True)
class FunctionalJudgeStageResult:
    assignment_count: int
    pass_count: int
    pass_outcome_count: int
    fail_outcome_count: int
    unknown_outcome_count: int


@dataclass(frozen=True, slots=True)
class _Snapshot:
    input_paths: tuple[Path, ...]
    input_sha256: tuple[str, ...]
    manifest: RandomizationManifestRecord
    assignments: tuple[AssignmentRecord, ...]
    requests: tuple[GenerationRequestRecord, ...]
    executions: tuple[AssignmentExecutionRecord, ...]
    codes: tuple[CanonicalGeneratedCodeRecord, ...]
    contracts: tuple[TaskFunctionalContractRecord, ...]
    variants: tuple[PromptVariantRecord, ...]


def _error(message: str = "functional judge stage failed validation") -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage=_STAGE,
        message=message,
        retryable=False,
    )


def _read(path: Path, model: type, *, allow_empty: bool) -> tuple:
    return tuple(
        read_jsonl(
            path,
            model,
            required=True,
            allow_empty=allow_empty,
            max_records=_MAX_RECORDS,
            max_line_chars=_MAX_LINE_CHARS,
            max_total_chars=_MAX_TOTAL_CHARS,
            stage=_STAGE,
        )
    )


def _validate_passes(
    assignments: tuple[AssignmentRecord, ...],
    passes: tuple[FunctionalJudgePassRecord, ...],
    outcomes: tuple[ProgramFunctionalOutcomeRecord, ...],
    policy_sha256: str,
    mode: str,
) -> None:
    assignment_ids = {item.assignment_id for item in assignments}
    outcome_by_assignment = {item.assignment_id: item for item in outcomes}
    if len(outcome_by_assignment) != len(outcomes):
        raise _error()
    seen: set[tuple[str, str]] = set()
    for item in passes:
        key = (item.assignment_id, item.pass_id)
        outcome = outcome_by_assignment.get(item.assignment_id)
        if (
            key in seen
            or item.assignment_id not in assignment_ids
            or outcome is None
            or item.contract_id != outcome.contract_id
            or item.evaluator_policy_sha256 != policy_sha256
        ):
            raise _error()
        seen.add(key)
    for assignment_id in assignment_ids:
        pass_ids = {pass_id for candidate, pass_id in seen if candidate == assignment_id}
        expected_pass_ids = {"A"} if mode == "single_pass" else {"A", "B"}
        if pass_ids and pass_ids != expected_pass_ids:
            raise _error()


def run_functional_judge_stage(
    config: AppConfig,
    store: RunStore,
    *,
    force: bool = False,
) -> FunctionalJudgeStageResult:
    """Evaluate every assignment using only the frozen app configuration."""

    if type(config) is not AppConfig or type(store) is not RunStore or store.config != config:
        raise _error("functional judge stage arguments failed validation")
    contract_value = config.data.task_functional_contracts_path
    if not config.functional_judge.enabled or contract_value is None:
        raise _error("functional judge stage configuration is unavailable")
    selected_judge = create_functional_judge(config)
    if type(selected_judge) is not LLMFunctionalJudge:
        raise _error("functional judge stage evaluator failed validation")

    variant_paths = tuple(
        store.path("interventions", name) for name, _model in PROMPT_VARIANT_OUTPUTS
    )
    randomization_paths = tuple(
        store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS
    )
    generation_paths = tuple(
        store.path("generation", name) for name, _model in CONFIRMATION_GENERATION_OUTPUTS
    )
    producer_paths = {
        "build-confirmation-variants": variant_paths,
        "randomize-confirmation": randomization_paths,
        "generate-confirmation": generation_paths,
    }
    contract_path = Path(contract_value)
    prompt_path = store.path("inputs", "prompts.jsonl")
    manifest_paths = tuple(store.path(".stages", f"{name}.json") for name in producer_paths)
    input_paths = (
        contract_path,
        prompt_path,
        *variant_paths,
        *randomization_paths,
        *generation_paths,
        *manifest_paths,
    )
    output_specs = tuple(
        JsonlOutputSpec(
            store.path("analysis", name),
            model,
            require_nonempty=index == 1,
            max_records=_MAX_RECORDS * (2 if index == 0 else 1),
            max_line_chars=_MAX_LINE_CHARS,
            max_total_chars=_MAX_TOTAL_CHARS,
        )
        for index, (name, model) in enumerate(FUNCTIONAL_JUDGE_OUTPUTS)
    )
    snapshot: _Snapshot | None = None
    built: tuple[tuple[BaseModel, ...], ...] | None = None

    def capture_input_snapshot() -> tuple[str, ...]:
        nonlocal snapshot
        if snapshot is not None:
            raise _error()
        digests = tuple(sha256_path(path) for path in input_paths)
        contracts = _read(contract_path, TaskFunctionalContractRecord, allow_empty=False)
        prompts = _read(prompt_path, PromptRecord, allow_empty=False)
        variants = next(
            _read(path, model, allow_empty=False)
            for path, (name, model) in zip(variant_paths, PROMPT_VARIANT_OUTPUTS, strict=True)
            if name == "prompt_variants.jsonl"
        )
        randomization_groups = tuple(
            _read(path, model, allow_empty=False)
            for path, (_name, model) in zip(randomization_paths, RANDOMIZATION_OUTPUTS, strict=True)
        )
        generation_groups = tuple(
            _read(path, model, allow_empty=index == 2)
            for index, (path, (_name, model)) in enumerate(
                zip(generation_paths, CONFIRMATION_GENERATION_OUTPUTS, strict=True)
            )
        )
        if len(randomization_groups[0]) != 1:
            raise _error()
        manifest = randomization_groups[0][0]
        assignments = randomization_groups[1]
        validate_confirmation_generation_bundle(
            manifest,
            assignments,
            variants,
            config,
            generation_groups[0],
            generation_groups[1],
            generation_groups[2],
        )
        task_ids = {item.experimental_unit.task_id for item in assignments}
        contract_by_task = {item.task_id: item for item in contracts}
        variant_by_id = {item.variant_id: item for item in variants}
        source_by_id = {item.prompt_id: item for item in prompts}
        if (
            len(contract_by_task) != len(contracts)
            or len(variant_by_id) != len(variants)
            or len(source_by_id) != len(prompts)
            or set(contract_by_task) != task_ids
        ):
            raise _error("task functional contract coverage failed validation")
        for assignment in assignments:
            contract = contract_by_task[assignment.experimental_unit.task_id]
            variant = variant_by_id.get(assignment.variant_id)
            source = source_by_id.get(contract.source_prompt_id)
            if (
                variant is None
                or source is None
                or variant.task_id != contract.task_id
                or variant.source_prompt_id != contract.source_prompt_id
                or variant.language != contract.language
                or source.task_id != contract.task_id
                or source.prompt_sha256 != contract.source_prompt_sha256
                or source.language != contract.language
            ):
                raise _error("task functional contract provenance failed validation")
        snapshot = _Snapshot(
            input_paths=input_paths,
            input_sha256=digests,
            manifest=manifest,
            assignments=assignments,
            requests=generation_groups[0],
            executions=generation_groups[1],
            codes=generation_groups[2],
            contracts=contracts,
            variants=variants,
        )
        return digests

    def verify_input_snapshot() -> None:
        if snapshot is None or tuple(sha256_path(path) for path in input_paths) != (
            snapshot.input_sha256
        ):
            raise _error("functional judge stage inputs changed during execution")

    def build() -> tuple[tuple[BaseModel, ...], ...]:
        nonlocal built
        if snapshot is None:
            raise _error()
        execution_by_assignment = {item.assignment_id: item for item in snapshot.executions}
        code_by_assignment = {item.assignment_id: item for item in snapshot.codes}
        contract_by_task = {item.task_id: item for item in snapshot.contracts}
        passes: list[FunctionalJudgePassRecord] = []
        outcomes: list[ProgramFunctionalOutcomeRecord] = []
        for assignment in sorted(snapshot.assignments, key=lambda item: item.assignment_id):
            produced_passes, outcome = selected_judge.evaluate(
                assignment,
                execution_by_assignment[assignment.assignment_id],
                code_by_assignment.get(assignment.assignment_id),
                contract_by_task[assignment.experimental_unit.task_id],
            )
            passes.extend(produced_passes)
            outcomes.append(outcome)
        ordered_passes = tuple(sorted(passes, key=lambda item: (item.assignment_id, item.pass_id)))
        ordered_outcomes = validate_program_functional_outcomes(
            snapshot.assignments,
            snapshot.contracts,
            outcomes,
            evaluator_policy_sha256=selected_judge.policy_sha256,
        )
        _validate_passes(
            snapshot.assignments,
            ordered_passes,
            ordered_outcomes,
            selected_judge.policy_sha256,
            selected_judge.mode,
        )
        built = (ordered_passes, ordered_outcomes)
        return built

    def validate_staged_outputs(
        groups: tuple[tuple[BaseModel | dict[str, object], ...], ...],
    ) -> None:
        if snapshot is None or built is None or groups != built:
            raise _error("functional judge output bundle failed validation")

    with store.hold_dependency_stages(tuple(producer_paths)):
        for stage, paths in producer_paths.items():
            store.require_committed_output(
                stage,
                paths,
                expected_catalog_sha256=(
                    PROMPT_FEATURE_CATALOG_SHA256
                    if stage == "build-confirmation-variants"
                    else None
                ),
            )
        execute_jsonl_stage_transaction(
            store,
            stage=_STAGE,
            inputs=input_paths,
            outputs=output_specs,
            force=force,
            build=build,
            policy_sha256=selected_judge.policy_sha256,
            capture_input_snapshot=capture_input_snapshot,
            verify_input_snapshot=verify_input_snapshot,
            validate_staged_outputs=validate_staged_outputs,
        )
    passes = _read(output_specs[0].path, FunctionalJudgePassRecord, allow_empty=True)
    outcomes = _read(output_specs[1].path, ProgramFunctionalOutcomeRecord, allow_empty=False)
    statuses = [item.status.value for item in outcomes]
    return FunctionalJudgeStageResult(
        assignment_count=len(outcomes),
        pass_count=len(passes),
        pass_outcome_count=statuses.count("pass"),
        fail_outcome_count=statuses.count("fail"),
        unknown_outcome_count=statuses.count("unknown"),
    )


__all__ = [
    "FUNCTIONAL_JUDGE_OUTPUTS",
    "FunctionalJudgeStageResult",
    "run_functional_judge_stage",
]
