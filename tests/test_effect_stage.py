from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from secaware.config import AppConfig
from secaware.errors import SecAwareError
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import canonical_sha256, sha256_path
from secaware.pipeline.manifest import read_stage_manifest
from secaware.io.transaction import ArtifactTransaction, TransactionStateError
import secaware.pipeline.stage_contracts as stage_contracts
import secaware.pipeline.stages.confirmation_generation as confirmation_generation_module
import secaware.pipeline.stages.confirmation_oracle as confirmation_oracle_module
import secaware.pipeline.stages.effects as effects_module
import secaware.pipeline.stages.prompt_variants as prompt_variants_module
import secaware.pipeline.stages.randomization as randomization_module
from secaware.analysis.itt import ITTEstimationResult
from secaware.pipeline.stages.confirmation_generation import (
    CONFIRMATION_GENERATION_OUTPUTS,
    run_confirmation_generation_stage,
)
from secaware.pipeline.stages.effects import (
    EFFECT_STAGE_INPUTS,
    EFFECT_STAGE_OUTPUTS,
    effects_stage,
)
from secaware.pipeline.stages.fci_discovery import FCI_DISCOVERY_OUTPUTS
from secaware.pipeline.stages.prompt_variants import (
    PROMPT_VARIANT_OUTPUTS,
    run_prompt_variant_freeze_stage,
)
from secaware.pipeline.stages.randomization import (
    RANDOMIZATION_OUTPUTS,
    run_confirmation_randomization_stage,
)
from secaware.schema.causal import FrozenHypothesisRecord
from secaware.schema.oracle import (
    AnalyzerProvenanceRecord,
    OracleEvaluability,
    OracleRecord,
    SecurityLabel,
)
from secaware.schema.outcomes import (
    AnalysisFailureRecord,
    AnalysisFailureReason,
    AnalysisStage,
    AssignmentOutcomeRecord,
    ContrastSpecRecord,
    EffectBootstrapDrawRecord,
    FunctionalOutcomeRecord,
    ITTEffectRecord,
)
from secaware.schema.records import CanonicalGeneratedCodeRecord
from test_prompt_variant_freeze_stage import _stage_store


EXPECTED_OUTPUTS = (
    "analysis/assignment_outcomes.jsonl",
    "analysis/contrast_specs.jsonl",
    "analysis/effect_bootstrap_draws.jsonl",
    "analysis/itt_effects.jsonl",
    "analysis/effect_failures.jsonl",
)


def _commit_confirmation_oracles(store: RunStore) -> None:
    codes = tuple(
        read_jsonl(
            store.path("generation", "confirmation_code.jsonl"),
            CanonicalGeneratedCodeRecord,
            required=True,
            allow_empty=True,
        )
    )
    analyzers = (
        AnalyzerProvenanceRecord(
            schema_version="1.0", analyzer="semgrep", version="1", policy_sha256="a" * 64
        ),
        AnalyzerProvenanceRecord(
            schema_version="1.0", analyzer="bandit", version="1", policy_sha256="b" * 64
        ),
    )
    records = tuple(
        sorted(
            (
                OracleRecord(
                    schema_version="1.2",
                    request_id=code.request_id,
                    code_id=code.code_id,
                    code_sha256=code.code_sha256,
                    prompt_id=code.prompt_id,
                    condition="confirm_arm",
                    model_id=code.model_id,
                    seed_id=code.seed_id,
                    hypothesis_id=code.hypothesis_id,
                    assignment_id=code.assignment_id,
                    target_spec_id=code.target_spec_id,
                    target_instance_id=code.target_instance_id,
                    arm_protocol_id=code.arm_protocol_id,
                    protocol_instance_id=code.protocol_instance_id,
                    variant_id=code.variant_id,
                    arm_role=code.arm_role,
                    parse_ok=True,
                    functional_ok=True,
                    security_label=SecurityLabel.SECURE,
                    evaluability=OracleEvaluability.EVALUABLE,
                    severity="none",
                    findings=(),
                    analyzers=analyzers,
                )
                for code in codes
            ),
            key=lambda item: item.request_id,
        )
    )
    path = store.path("oracle", "confirmation_oracle.jsonl")
    policy = "c" * 64
    assert not store.should_skip_stage(
        "run-oracle-confirmation", (), (path,), False, policy_sha256=policy
    )
    write_jsonl(path, records)
    assert (
        tuple(
            read_jsonl(
                path,
                OracleRecord,
                required=True,
                allow_empty=True,
            )
        )
        == records
    )
    store.seal_stage_outputs("run-oracle-confirmation", (path,))
    store.record_stage("run-oracle-confirmation", (), (path,), policy_sha256=policy)


def _base_store(
    root: Path,
    *,
    rfci_enabled: bool = False,
    task_count: int = 20,
    confirmation_feature_ids: tuple[str, ...] | None = None,
    hypothesis_records: tuple[FrozenHypothesisRecord, ...] | None = None,
    discovery_min_independent_tasks: int = 20,
    randomization_min_independent_tasks: int = 20,
) -> tuple[AppConfig, RunStore]:
    config, store = _stage_store(
        root,
        task_count=task_count,
        confirmation_feature_ids=confirmation_feature_ids,
        hypothesis_records=hypothesis_records,
        rfci_enabled=rfci_enabled,
        discovery_min_independent_tasks=discovery_min_independent_tasks,
        randomization_min_independent_tasks=randomization_min_independent_tasks,
    )
    run_prompt_variant_freeze_stage(config, store, force=False)
    run_confirmation_randomization_stage(config, store, force=False)
    run_confirmation_generation_stage(config, store, force=False)
    _commit_confirmation_oracles(store)
    return config, store


@pytest.fixture(scope="module")
def committed_base(tmp_path_factory: pytest.TempPathFactory):
    return _base_store(tmp_path_factory.mktemp("effect-stage-base"))


def _artifact_bytes(store: RunStore) -> tuple[bytes, ...]:
    return tuple((store.root / relative).read_bytes() for relative in EXPECTED_OUTPUTS) + (
        store.path(".stages", "estimate-confirmation-effects.json").read_bytes(),
    )


def _commit_adversarial_producer_bundle(
    store: RunStore,
    stage: str,
    outputs: tuple[tuple[Path, type, tuple], ...],
) -> None:
    paths = tuple(path for path, _model, _records in outputs)
    assert not store.should_skip_stage(stage, (), paths, True)
    for path, model, records in outputs:
        write_jsonl(path, records)
        assert (
            tuple(
                read_jsonl(
                    path,
                    model,
                    required=True,
                    allow_empty=not records,
                )
            )
            == records
        )
    store.seal_stage_outputs(stage, paths)
    store.record_stage(stage, (), paths)


def test_effect_stage_declares_exact_ordered_outputs_and_no_jci_rfci_inputs() -> None:
    assert tuple(path.as_posix() for path, _model in EFFECT_STAGE_OUTPUTS) == EXPECTED_OUTPUTS
    assert all("jci" not in path.name and "rfci" not in path.name for path in EFFECT_STAGE_INPUTS)


def test_effect_output_specs_cover_bounded_estimator_and_cluster_artifacts(
    committed_base,
) -> None:
    _config, store = committed_base
    specs = effects_module._effect_output_specs(store)

    assert len(specs) == len(EFFECT_STAGE_OUTPUTS)
    assert all(spec.max_records > 0 for spec in specs)
    assert all(spec.max_line_chars > 0 for spec in specs)
    assert all(spec.max_total_chars > 0 for spec in specs)
    draw_spec = specs[2]
    assert draw_spec.max_records == 125_000
    assert draw_spec.max_records > 100_000
    assert draw_spec.max_line_chars > 16 * 1024 * 1024
    assert draw_spec.max_total_chars <= 1_000_000_000
    assert specs[3].max_records == specs[4].max_records == 125_000
    assert specs[3].max_total_chars <= 256_000_000
    assert specs[4].max_total_chars <= 256_000_000


def test_final_output_reads_use_exact_finite_specs_on_publish_and_skip(
    committed_base,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = committed_base
    specs = effects_module._effect_output_specs(store)
    expected_paths = {spec.path for spec in specs}
    observed: list[tuple[Path, int | None, int | None, int | None]] = []
    delegate = effects_module.read_jsonl

    def tracking_read(path, model, **kwargs):
        normalized = Path(path)
        if normalized in expected_paths:
            observed.append(
                (
                    normalized,
                    kwargs.get("max_records"),
                    kwargs.get("max_line_chars"),
                    kwargs.get("max_total_chars"),
                )
            )
        return delegate(path, model, **kwargs)

    monkeypatch.setattr(effects_module, "read_jsonl", tracking_read)
    for force in (True, False):
        observed.clear()
        effects_stage(config, store, force=force)
        assert observed == [
            (
                spec.path,
                spec.max_records,
                spec.max_line_chars,
                spec.max_total_chars,
            )
            for spec in specs
        ]


def test_all_producer_and_external_reads_use_explicit_finite_limits(
    committed_base,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = committed_base
    output_paths = {spec.path for spec in effects_module._effect_output_specs(store)}
    observed: list[tuple[int | None, int | None, int | None]] = []
    delegate = effects_module.read_jsonl

    def tracking_read(path, model, **kwargs):
        if Path(path) not in output_paths:
            observed.append(
                (
                    kwargs.get("max_records"),
                    kwargs.get("max_line_chars"),
                    kwargs.get("max_total_chars"),
                )
            )
        return delegate(path, model, **kwargs)

    monkeypatch.setattr(effects_module, "read_jsonl", tracking_read)
    effects_stage(config, store, force=True)

    assert observed
    assert set(observed) == {(100_000, 4_000_000, 256_000_000)}


@pytest.mark.parametrize(
    ("content", "limits"),
    (
        ("{}\n{}\n", (1, 100, 100)),
        ('{"value":"123456"}\n', (10, 5, 100)),
        ("{}\n{}\n", (10, 100, 3)),
    ),
)
def test_bounded_input_reader_rejects_record_line_and_total_overflow(
    tmp_path: Path,
    content: str,
    limits: tuple[int, int, int],
) -> None:
    path = tmp_path / "bounded-input.jsonl"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(SecAwareError):
        effects_module._read(
            path,
            None,
            allow_empty=True,
            limits=effects_module._JsonlReadLimits(*limits),
        )


@pytest.mark.parametrize(
    "module",
    (
        prompt_variants_module,
        randomization_module,
        confirmation_generation_module,
        confirmation_oracle_module,
    ),
)
def test_preceding_future_guards_cover_canonical_effect_stage(module) -> None:
    assert "estimate-confirmation-effects" in module._FUTURE_STAGE_NAMES
    assert "effects" in module._FUTURE_STAGE_NAMES


def test_effect_stage_publishes_complete_atomic_artifact(committed_base, tmp_path: Path) -> None:
    config, store = committed_base

    effects_stage(config, store, force=False)

    models = (
        AssignmentOutcomeRecord,
        ContrastSpecRecord,
        EffectBootstrapDrawRecord,
        ITTEffectRecord,
        AnalysisFailureRecord,
    )
    groups = tuple(
        tuple(
            read_jsonl(
                store.root / relative,
                model,
                required=True,
                allow_empty=index in {2, 3, 4},
            )
        )
        for index, (relative, model) in enumerate(zip(EXPECTED_OUTPUTS, models, strict=True))
    )
    assert groups[0] and groups[1]
    assert len(groups[2]) == len(groups[3]) * config.analysis.bootstrap_samples
    for effect in groups[3]:
        effect_draws = tuple(draw for draw in groups[2] if draw.effect_id == effect.effect_id)
        expected = (
            0
            if effect.status == "unsupported_missing_functional_outcome"
            else config.analysis.bootstrap_samples
        )
        assert len(effect_draws) == expected
        assert len({draw.replicate_index for draw in effect_draws}) == expected
    manifest = read_stage_manifest(store.path(".stages", "estimate-confirmation-effects.json"))
    assert tuple(manifest.outputs) == EXPECTED_OUTPUTS
    assert set(manifest.output_sha256) == set(EXPECTED_OUTPUTS)


def test_effect_stage_holds_exact_full_producer_bundles(
    committed_base, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = committed_base
    held: dict[str, tuple[str, ...]] = {}
    delegate = store.require_committed_output

    def tracking(stage, outputs, **kwargs):
        held[stage] = tuple(path.relative_to(store.root).as_posix() for path in outputs)
        return delegate(stage, outputs, **kwargs)

    monkeypatch.setattr(store, "require_committed_output", tracking)
    effects_stage(config, store, force=False)

    assert held == {
        "build-confirmation-variants": tuple(
            f"interventions/{name}" for name, _model in PROMPT_VARIANT_OUTPUTS
        ),
        "fci-discovery": tuple(f"discovery/{name}" for name, _model in FCI_DISCOVERY_OUTPUTS),
        "generate-confirmation": tuple(
            f"generation/{name}" for name, _model in CONFIRMATION_GENERATION_OUTPUTS
        ),
        "randomize-confirmation": tuple(
            f"interventions/{name}" for name, _model in RANDOMIZATION_OUTPUTS
        ),
        "run-oracle-confirmation": ("oracle/confirmation_oracle.jsonl",),
    }


def test_force_failure_restores_all_five_outputs_and_manifest(
    committed_base, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = committed_base
    effects_stage(config, store, force=False)
    before = _artifact_bytes(store)
    monkeypatch.setattr(
        effects_module,
        "calculate_itt",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("private")),
    )

    with pytest.raises(Exception):
        effects_stage(config, store, force=True)

    assert _artifact_bytes(store) == before


def test_force_mid_install_failure_restores_all_outputs_and_manifest(
    committed_base, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = committed_base
    effects_stage(config, store, force=False)
    before = _artifact_bytes(store)
    delegate = ArtifactTransaction.install
    failed = False

    def fail_fourth_install(self, index, candidate):
        nonlocal failed
        if index == 3 and not failed:
            failed = True
            raise TransactionStateError("private")
        return delegate(self, index, candidate)

    monkeypatch.setattr(ArtifactTransaction, "install", fail_fourth_install)
    with pytest.raises(Exception):
        effects_stage(config, store, force=True)

    assert failed
    assert _artifact_bytes(store) == before


def test_insufficient_support_publishes_exactly_one_typed_failure_per_coordinate(
    committed_base, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = committed_base

    def insufficient(outcomes, analysis_config, *, protocols, contrasts, **_kwargs):
        groups = {
            (row.hypothesis_id, row.target_spec_id, row.arm_protocol_id, row.model_id)
            for row in outcomes
        }
        failures = tuple(
            AnalysisFailureRecord.from_content(
                stage=AnalysisStage.EFFECTS,
                subject_id="effect_coordinate_"
                + canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "effect_coordinate": [
                            *group,
                            contrast.contrast_id,
                            contrast.outcome_id,
                        ],
                    }
                ),
                reason_code=AnalysisFailureReason.INSUFFICIENT_SUPPORT,
                config_sha256="a" * 64,
                input_bundle_sha256="b" * 64,
            )
            for group, contrast in (
                (group, contrast)
                for group in sorted(groups)
                for contrast in contrasts
                if contrast.arm_protocol_id == group[2]
            )
        )
        return ITTEstimationResult((), (), failures)

    monkeypatch.setattr(effects_module, "calculate_itt", insufficient)

    effects_stage(config, store, force=True)

    contrasts = read_jsonl(
        store.path("analysis", "contrast_specs.jsonl"),
        ContrastSpecRecord,
        required=True,
        allow_empty=False,
    )
    effects = read_jsonl(
        store.path("analysis", "itt_effects.jsonl"),
        ITTEffectRecord,
        required=True,
        allow_empty=True,
    )
    failures = read_jsonl(
        store.path("analysis", "effect_failures.jsonl"),
        AnalysisFailureRecord,
        required=True,
        allow_empty=True,
    )
    assert not effects
    assert len(failures) == len(contrasts)
    assert {item.reason_code.value for item in failures} == {"insufficient_support"}


def test_empty_committed_assignment_universe_is_hard_and_preserves_old_commit(
    tmp_path: Path,
) -> None:
    config, store = _base_store(tmp_path)
    effects_stage(config, store, force=True)
    before = _artifact_bytes(store)
    paths = tuple(store.path("interventions", name) for name, _model in RANDOMIZATION_OUTPUTS)
    manifests = tuple(
        read_jsonl(
            paths[0],
            RANDOMIZATION_OUTPUTS[0][1],
            required=True,
            allow_empty=False,
        )
    )
    _commit_adversarial_producer_bundle(
        store,
        "randomize-confirmation",
        (
            (paths[0], RANDOMIZATION_OUTPUTS[0][1], manifests),
            (paths[1], RANDOMIZATION_OUTPUTS[1][1], ()),
        ),
    )

    with pytest.raises(Exception):
        effects_stage(config, store, force=False)

    assert _artifact_bytes(store) == before


def test_empty_committed_frozen_hypothesis_universe_is_hard_and_preserves_old_commit(
    tmp_path: Path,
) -> None:
    config, store = _base_store(tmp_path)
    effects_stage(config, store, force=True)
    before = _artifact_bytes(store)
    outputs = []
    for index, (name, model) in enumerate(FCI_DISCOVERY_OUTPUTS):
        path = store.path("discovery", name)
        records = tuple(read_jsonl(path, model, required=True, allow_empty=index != 6))
        outputs.append((path, model, () if index == 6 else records))
    _commit_adversarial_producer_bundle(
        store,
        "fci-discovery",
        tuple(outputs),
    )

    with pytest.raises(Exception):
        effects_stage(config, store, force=False)

    assert _artifact_bytes(store) == before


def test_partial_and_tampered_required_producer_bundles_preserve_old_commit(
    tmp_path: Path,
) -> None:
    config, store = _base_store(tmp_path)
    effects_stage(config, store, force=True)
    before = _artifact_bytes(store)
    path = store.path("interventions", "assignments.jsonl")
    original = path.read_bytes()

    path.unlink()
    with pytest.raises(Exception):
        effects_stage(config, store, force=False)
    assert _artifact_bytes(store) == before

    path.write_bytes(original + b"\n")
    with pytest.raises(Exception):
        effects_stage(config, store, force=False)
    assert _artifact_bytes(store) == before

    path.write_bytes(original)


def test_concurrent_producer_mutation_fails_and_publishes_nothing(
    committed_base, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = _base_store(tmp_path)
    delegate = effects_module.calculate_itt

    def mutate_then_calculate(*args, **kwargs):
        path = store.path("oracle", "confirmation_oracle.jsonl")
        path.write_bytes(path.read_bytes() + b"\n")
        return delegate(*args, **kwargs)

    monkeypatch.setattr(effects_module, "calculate_itt", mutate_then_calculate)
    with pytest.raises(Exception):
        effects_stage(config, store, force=False)

    assert not any((store.root / relative).exists() for relative in EXPECTED_OUTPUTS)
    assert not store.path(".stages", "estimate-confirmation-effects.json").exists()


def test_partial_optional_functional_commit_is_a_hard_failure(
    committed_base, tmp_path: Path
) -> None:
    config, store = _base_store(tmp_path)
    store.path(".stages", "import-functional-outcomes.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(Exception):
        effects_stage(config, store, force=False)

    assert not any((store.root / relative).exists() for relative in EXPECTED_OUTPUTS)


def test_optional_functional_candidate_is_in_total_ordered_dependency_lease(
    committed_base, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = committed_base
    delegate = store.hold_dependency_stages
    captured: list[tuple[str, ...]] = []

    def tracking(stages):
        captured.append(tuple(stages))
        return delegate(stages)

    monkeypatch.setattr(store, "hold_dependency_stages", tracking)
    effects_stage(config, store, force=False)

    assert captured == [
        (
            "build-confirmation-variants",
            "fci-discovery",
            "randomize-confirmation",
            "generate-confirmation",
            "run-oracle-confirmation",
            "import-functional-outcomes",
        )
    ]


@pytest.mark.parametrize("relative_outputs", (EXPECTED_OUTPUTS[:-1], EXPECTED_OUTPUTS[::-1]))
def test_run_store_rejects_incomplete_or_reordered_effect_output_contract(
    committed_base, tmp_path: Path, relative_outputs: tuple[str, ...]
) -> None:
    _config, store = committed_base
    with pytest.raises(SecAwareError, match="output contract"):
        store._validate_stage_output_contract("estimate-confirmation-effects", relative_outputs)


@pytest.mark.parametrize(
    ("binding", "replacement"),
    (
        ("RNG_VERSION", "test-cluster-bootstrap-rng-v2"),
        ("MAX_ESTIMATOR_ARTIFACT_RECORDS", 124_999),
        ("MAX_ESTIMATOR_DRAW_RECORDS", 124_999),
    ),
)
def test_effect_stage_requires_output_seal_and_resource_bound_contract_fingerprint(
    committed_base,
    monkeypatch: pytest.MonkeyPatch,
    binding: str,
    replacement: object,
) -> None:
    _config, store = committed_base
    assert store._requires_output_seal("estimate-confirmation-effects")
    inputs = tuple(
        store.root / path for path in EFFECT_STAGE_INPUTS if (store.root / path).exists()
    )
    contract_before = stage_contracts.effect_stage_contract_sha256("estimate-confirmation-effects")
    fingerprint_before = store.stage_fingerprint("estimate-confirmation-effects", inputs)

    monkeypatch.setattr(stage_contracts, binding, replacement)

    assert (
        stage_contracts.effect_stage_contract_sha256("estimate-confirmation-effects")
        != contract_before
    )
    assert store.stage_fingerprint("estimate-confirmation-effects", inputs) != fingerprint_before


def test_valid_skip_is_invalidated_and_rebuilt_after_output_tamper(
    committed_base, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = committed_base
    effects_stage(config, store, force=True)
    committed = _artifact_bytes(store)
    manifest = read_stage_manifest(store.path(".stages", "estimate-confirmation-effects.json"))
    assert manifest.output_sha256 == {
        relative: sha256_path(store.root / relative) for relative in EXPECTED_OUTPUTS
    }
    calculate = effects_module.calculate_itt
    calculate_calls = 0

    def tracking_calculate(*args, **kwargs):
        nonlocal calculate_calls
        calculate_calls += 1
        return calculate(*args, **kwargs)

    monkeypatch.setattr(effects_module, "calculate_itt", tracking_calculate)
    effects_stage(config, store, force=False)
    assert calculate_calls == 0
    assert _artifact_bytes(store) == committed
    path = store.path("analysis", "itt_effects.jsonl")
    expected = path.read_bytes()
    path.write_bytes(expected + b"\n")

    effects_stage(config, store, force=False)

    assert calculate_calls == 1
    assert path.read_bytes() == expected


def test_staged_bundle_validation_precedes_first_install(
    committed_base, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = committed_base
    coverage = effects_module._validate_output_coverage
    install = ArtifactTransaction.install
    coverage_calls = 0
    install_calls = 0

    def tracking_coverage(*args, **kwargs):
        nonlocal coverage_calls
        coverage_calls += 1
        return coverage(*args, **kwargs)

    def tracking_install(self, index, candidate):
        nonlocal install_calls
        assert coverage_calls >= 2
        install_calls += 1
        return install(self, index, candidate)

    monkeypatch.setattr(effects_module, "_validate_output_coverage", tracking_coverage)
    monkeypatch.setattr(ArtifactTransaction, "install", tracking_install)
    effects_stage(config, store, force=True)

    assert coverage_calls >= 3
    assert install_calls == len(EFFECT_STAGE_OUTPUTS)


def test_manifest_record_failure_restores_old_commit_byte_for_byte(
    committed_base, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = committed_base
    effects_stage(config, store, force=True)
    before = _artifact_bytes(store)

    def fail_record(*_args, **_kwargs):
        raise RuntimeError("private")

    monkeypatch.setattr(store, "record_stage", fail_record)
    with pytest.raises(Exception):
        effects_stage(config, store, force=True)

    assert _artifact_bytes(store) == before


def test_dependency_lease_remains_active_through_install_seal_and_manifest_commit(
    committed_base, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = committed_base
    hold = store.hold_dependency_stages
    install = ArtifactTransaction.install
    seal = store.seal_stage_outputs
    record = store.record_stage
    active = False
    observed = {"install": 0, "seal": 0, "record": 0}

    @contextmanager
    def tracking_hold(stages):
        nonlocal active
        with hold(stages) as leased:
            active = True
            try:
                yield leased
            finally:
                active = False

    def tracking_install(self, index, candidate):
        assert active
        observed["install"] += 1
        return install(self, index, candidate)

    def tracking_seal(stage, outputs):
        assert active
        observed["seal"] += 1
        return seal(stage, outputs)

    def tracking_record(*args, **kwargs):
        assert active
        observed["record"] += 1
        return record(*args, **kwargs)

    monkeypatch.setattr(store, "hold_dependency_stages", tracking_hold)
    monkeypatch.setattr(ArtifactTransaction, "install", tracking_install)
    monkeypatch.setattr(store, "seal_stage_outputs", tracking_seal)
    monkeypatch.setattr(store, "record_stage", tracking_record)
    effects_stage(config, store, force=True)

    assert not active
    assert observed == {"install": 5, "seal": 1, "record": 1}


def test_empty_contrast_universe_is_hard_and_preserves_old_commit(
    committed_base, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, store = committed_base
    effects_stage(config, store, force=True)
    before = _artifact_bytes(store)
    monkeypatch.setattr(effects_module, "materialize_contrasts", lambda _protocols: ())

    with pytest.raises(Exception):
        effects_stage(config, store, force=True)

    assert _artifact_bytes(store) == before


def test_optional_functional_output_only_is_partial_and_preserves_effect_commit(
    committed_base,
) -> None:
    config, store = committed_base
    effects_stage(config, store, force=True)
    before = _artifact_bytes(store)
    path = store.path("analysis", "functional_outcomes.jsonl")
    write_jsonl(path, ())
    try:
        with pytest.raises(Exception):
            effects_stage(config, store, force=False)
        assert _artifact_bytes(store) == before
    finally:
        path.unlink(missing_ok=True)


def test_optional_functional_full_commit_is_consumed_and_tamper_fails_closed(
    committed_base,
) -> None:
    config, store = committed_base
    path = store.path("analysis", "functional_outcomes.jsonl")
    assert not store.should_skip_stage("import-functional-outcomes", (), (path,), False)
    write_jsonl(path, ())
    assert (
        read_jsonl(
            path,
            FunctionalOutcomeRecord,
            required=True,
            allow_empty=True,
        )
        == []
    )
    store.seal_stage_outputs("import-functional-outcomes", (path,))
    store.record_stage("import-functional-outcomes", (), (path,))

    effects_stage(config, store, force=False)
    committed = _artifact_bytes(store)
    functional_bytes = path.read_bytes()
    path.write_bytes(functional_bytes + b"\n")
    try:
        with pytest.raises(Exception):
            effects_stage(config, store, force=False)
        assert _artifact_bytes(store) == committed
    finally:
        path.write_bytes(functional_bytes)


def _published_effect_bundle(store: RunStore):
    outcomes = tuple(
        read_jsonl(
            store.path("analysis", "assignment_outcomes.jsonl"),
            AssignmentOutcomeRecord,
            required=True,
            allow_empty=False,
        )
    )
    contrasts = tuple(
        read_jsonl(
            store.path("analysis", "contrast_specs.jsonl"),
            ContrastSpecRecord,
            required=True,
            allow_empty=False,
        )
    )
    draws = tuple(
        read_jsonl(
            store.path("analysis", "effect_bootstrap_draws.jsonl"),
            EffectBootstrapDrawRecord,
            required=True,
            allow_empty=True,
        )
    )
    effects = tuple(
        read_jsonl(
            store.path("analysis", "itt_effects.jsonl"),
            ITTEffectRecord,
            required=True,
            allow_empty=True,
        )
    )
    failures = tuple(
        read_jsonl(
            store.path("analysis", "effect_failures.jsonl"),
            AnalysisFailureRecord,
            required=True,
            allow_empty=True,
        )
    )
    return outcomes, contrasts, ITTEstimationResult(effects, draws, failures)


def test_effect_coverage_rejects_duplicate_coordinate_and_missing_supported_draw(
    committed_base,
) -> None:
    config, store = committed_base
    effects_stage(config, store, force=True)
    outcomes, contrasts, result = _published_effect_bundle(store)
    assert result.effects and result.draws
    supported = result.effects[0]
    missing_draws = tuple(
        draw
        for draw in result.draws
        if not (draw.effect_id == supported.effect_id and draw.replicate_index == 0)
    )

    with pytest.raises(Exception):
        effects_module._validate_output_coverage(
            outcomes,
            contrasts,
            ITTEstimationResult(result.effects, missing_draws, result.failures),
            bootstrap_samples=config.analysis.bootstrap_samples,
        )
    with pytest.raises(Exception):
        effects_module._validate_output_coverage(
            outcomes,
            contrasts,
            ITTEstimationResult((*result.effects, supported), result.draws, result.failures),
            bootstrap_samples=config.analysis.bootstrap_samples,
        )


@pytest.mark.parametrize("wrong_subject", (False, True))
def test_effect_coverage_rejects_non_effect_failure_and_failed_coordinate_draws(
    committed_base, wrong_subject: bool
) -> None:
    config, store = committed_base
    outcomes, contrasts, result = _published_effect_bundle(store)
    removed = result.effects[0]
    subject = "effect_coordinate_" + canonical_sha256(
        {
            "schema_version": "1.0",
            "effect_coordinate": [
                removed.hypothesis_id,
                removed.target_spec_id,
                removed.arm_protocol_id,
                removed.model_id,
                removed.contrast_id,
                removed.outcome_id,
            ],
        }
    )
    failure = AnalysisFailureRecord.from_content(
        stage=AnalysisStage.JCI,
        subject_id=("effect_coordinate_" + "f" * 64 if wrong_subject else subject),
        reason_code=AnalysisFailureReason.BACKEND_FAILURE,
        config_sha256="a" * 64,
        input_bundle_sha256="b" * 64,
    )
    remaining_effects = tuple(effect for effect in result.effects if effect is not removed)

    with pytest.raises(Exception):
        effects_module._validate_output_coverage(
            outcomes,
            contrasts,
            ITTEstimationResult(remaining_effects, result.draws, (failure,)),
            bootstrap_samples=config.analysis.bootstrap_samples,
        )
