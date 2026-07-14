from __future__ import annotations

import threading

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.config import AppConfig, load_config
from secaware.experiments.randomization import RandomizationError, build_randomization_blocks
from secaware.io.jsonl import read_jsonl
from secaware.io.run_store import RunStore
from secaware.io.transaction import ArtifactTransaction, TransactionStateError
from secaware.pipeline.manifest import read_stage_manifest
from secaware.pipeline.manifest import build_stage_fingerprint
import secaware.pipeline.stage_contracts as stage_contracts
import secaware.pipeline.stages.randomization as randomization_stage
from secaware.pipeline.stages.randomization import RANDOMIZATION_OUTPUTS
from secaware.pipeline.stages.prompt_variants import run_prompt_variant_freeze_stage
from secaware.pipeline.stages.randomization import run_confirmation_randomization_stage
from secaware.schema.experiments import AssignmentRecord, RandomizationManifestRecord
from secaware.schema.causal import FrozenHypothesisRecord
from secaware.schema.experiments import (
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    PreRandomizationExclusionRecord,
    PromptVariantRecord,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from test_prompt_variant_freeze_stage import _stage_store
from secaware import __version__


@pytest.fixture(scope="module")
def frozen_task4_store(tmp_path_factory: pytest.TempPathFactory):
    config, store = _stage_store(tmp_path_factory.mktemp("randomization"), task_count=20)
    run_prompt_variant_freeze_stage(config, store, force=False)
    return config, store


def test_randomization_stage_declares_atomic_manifest_and_assignment_outputs() -> None:
    assert RANDOMIZATION_OUTPUTS == (
        ("randomization_manifest.jsonl", RandomizationManifestRecord),
        ("assignments.jsonl", AssignmentRecord),
    )


def test_randomization_fingerprint_binds_global_seed_config_rng_and_schemas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_config("configs/demo.yaml")
    inputs = {"interventions/prompt_variants.jsonl": "a" * 64}

    def fingerprint(value: AppConfig) -> str:
        return build_stage_fingerprint(
            "randomize-confirmation",
            inputs,
            value.model_dump(mode="json"),
            stage_contract_sha256=stage_contracts.randomization_stage_contract_sha256(
                "randomize-confirmation"
            ),
            code_version=__version__,
        )

    baseline = fingerprint(config)
    global_seed_payload = config.model_dump(mode="json")
    global_seed_payload["run"]["random_seed"] += 1
    seed_slots_payload = config.model_dump(mode="json")
    seed_slots_payload["generation"]["confirmation_seeds"] = list(range(201, 213))
    randomization_payload = config.model_dump(mode="json")
    randomization_payload["randomization"]["max_blocks"] -= 1
    assert (
        len(
            {
                baseline,
                fingerprint(AppConfig.model_validate(global_seed_payload)),
                fingerprint(AppConfig.model_validate(seed_slots_payload)),
                fingerprint(AppConfig.model_validate(randomization_payload)),
            }
        )
        == 4
    )

    contract = stage_contracts.randomization_stage_contract_payload()
    assert {
        "rng_version",
        "app_config_schema",
        "generation_config_schema",
        "randomization_config_schema",
        "hypothesis_schema",
        "target_schema",
        "target_instance_schema",
        "protocol_schema",
        "protocol_instance_schema",
        "patch_schema",
        "proposal_schema",
        "prompt_tsg_schema",
        "graph_delta_schema",
        "variant_schema",
        "length_match_schema",
        "exclusion_schema",
        "producer_manifest_schema",
        "experimental_unit_schema",
        "assignment_schema",
        "manifest_schema",
    } <= set(contract)

    original_contract = stage_contracts.randomization_stage_contract_sha256(
        "randomize-confirmation"
    )
    monkeypatch.setattr(stage_contracts, "RNG_VERSION", "future-rng")
    assert (
        stage_contracts.randomization_stage_contract_sha256("randomize-confirmation")
        != original_contract
    )
    monkeypatch.setattr(stage_contracts, "RNG_VERSION", "sha256-rejection-fisher-yates-v1")
    original_schema_digest = stage_contracts._schema_sha256

    def drift_assignment_schema(model: type) -> str:
        if model is AssignmentRecord:
            return "f" * 64
        return original_schema_digest(model)

    monkeypatch.setattr(stage_contracts, "_schema_sha256", drift_assignment_schema)
    assert (
        stage_contracts.randomization_stage_contract_sha256("randomize-confirmation")
        != original_contract
    )


def test_task4_input_closure_rejects_omission_extra_and_coordinate_drift(
    frozen_task4_store,
) -> None:
    config, store = frozen_task4_store

    def records(name: str, model: type):
        return tuple(
            read_jsonl(
                store.path("interventions", name),
                model,
                required=True,
                allow_empty=True,
            )
        )

    targets = records("target_specs.jsonl", TargetSpecRecord)
    target_instances = records("target_instances.jsonl", TargetInstanceRecord)
    protocols = records("confirmation_protocols.jsonl", ConfirmationProtocolRecord)
    protocol_instances = records(
        "confirmation_protocol_instances.jsonl", ConfirmationProtocolInstanceRecord
    )
    variants = records("prompt_variants.jsonl", PromptVariantRecord)
    exclusions = records("pre_randomization_exclusions.jsonl", PreRandomizationExclusionRecord)
    hypotheses = tuple(
        read_jsonl(
            store.path("discovery", "hypotheses_frozen.jsonl"),
            FrozenHypothesisRecord,
            required=True,
            allow_empty=False,
        )
    )

    def build(**overrides):
        values = {
            "target_specs": targets,
            "target_instances": target_instances,
            "protocols": protocols,
            "protocol_instances": protocol_instances,
            "variants": variants,
            "exclusions": exclusions,
            "hypotheses": hypotheses,
            "max_blocks": config.randomization.max_blocks,
        }
        values.update(overrides)
        return build_randomization_blocks(**values)

    assert len(build()) == 20
    assert (
        build(
            target_specs=tuple(reversed(targets)),
            target_instances=tuple(reversed(target_instances)),
            protocols=tuple(reversed(protocols)),
            protocol_instances=tuple(reversed(protocol_instances)),
            variants=tuple(reversed(variants)),
            exclusions=tuple(reversed(exclusions)),
            hypotheses=tuple(reversed(hypotheses)),
        )
        == build()
    )
    mutations = (
        {"variants": variants[:-1]},
        {"variants": (*variants, variants[0])},
        {
            "variants": (
                variants[0].model_copy(update={"task_id": "wrong-task"}),
                *variants[1:],
            )
        },
        {
            "variants": (
                variants[0].model_copy(update={"target_spec_id": "target_" + "f" * 64}),
                *variants[1:],
            )
        },
        {"target_instances": target_instances[:-1]},
        {"protocol_instances": (*protocol_instances, protocol_instances[0])},
        {"hypotheses": (hypotheses[0].model_copy(update={"model_id": "wrong-model"}),)},
    )
    for mutation in mutations:
        with pytest.raises(RandomizationError):
            build(**mutation)


def test_randomization_stage_commits_balanced_assignments_before_generation(
    frozen_task4_store,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, store = frozen_task4_store

    real_install = ArtifactTransaction.install

    def fail_partial_install(self, index, candidate):
        if self.journal_path.name == ".randomize-confirmation.transaction.json" and index == 1:
            raise TransactionStateError()
        return real_install(self, index, candidate)

    monkeypatch.setattr(ArtifactTransaction, "install", fail_partial_install)
    with pytest.raises(SecAwareError) as rollback_error:
        run_confirmation_randomization_stage(config, store, force=False)
    assert rollback_error.value.code is ErrorCode.CONTRACT
    assert not store.path(".stages", "randomize-confirmation.json").exists()
    assert all(
        not store.path("interventions", name).exists() for name, _model in RANDOMIZATION_OUTPUTS
    )
    monkeypatch.setattr(ArtifactTransaction, "install", real_install)

    variant_path = store.path("interventions", "prompt_variants.jsonl")
    frozen_variant_bytes = variant_path.read_bytes()
    real_randomize = randomization_stage.randomize_protocols

    def mutate_after_plan(*args, **kwargs):
        randomized = real_randomize(*args, **kwargs)
        variant_path.write_bytes(frozen_variant_bytes + b"\n")
        return randomized

    monkeypatch.setattr(randomization_stage, "randomize_protocols", mutate_after_plan)
    with pytest.raises(SecAwareError) as drift_error:
        run_confirmation_randomization_stage(config, store, force=False)
    assert drift_error.value.message == "randomization inputs changed during execution"
    assert all(
        not store.path("interventions", name).exists() for name, _model in RANDOMIZATION_OUTPUTS
    )
    variant_path.write_bytes(frozen_variant_bytes)

    entered = threading.Event()
    release = threading.Event()

    def blocked_randomize(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=30)
        return real_randomize(*args, **kwargs)

    monkeypatch.setattr(randomization_stage, "randomize_protocols", blocked_randomize)
    completed: list[object] = []
    failures: list[BaseException] = []

    def run_stage() -> None:
        try:
            completed.append(run_confirmation_randomization_stage(config, store, force=False))
        except BaseException as error:  # exercised only to return thread failures to the test
            failures.append(error)

    thread = threading.Thread(target=run_stage)
    thread.start()
    assert entered.wait(timeout=30)
    competing_store = RunStore(config)
    with pytest.raises(SecAwareError) as lease_error:
        competing_store.invalidate_stage("fci-discovery")
    assert lease_error.value.code is ErrorCode.MANIFEST_CONFLICT
    release.set()
    thread.join(timeout=30)
    assert not thread.is_alive()
    assert failures == []
    assert len(completed) == 1
    result = completed[0]
    monkeypatch.setattr(randomization_stage, "randomize_protocols", real_randomize)

    manifests = read_jsonl(
        store.path("interventions", "randomization_manifest.jsonl"),
        RandomizationManifestRecord,
        required=True,
        allow_empty=False,
    )
    assignments = read_jsonl(
        store.path("interventions", "assignments.jsonl"),
        AssignmentRecord,
        required=True,
        allow_empty=False,
    )
    assert result.block_count == 20
    assert result.assignment_count == 240
    assert len(manifests) == 1
    assert manifests[0].assignment_ids == tuple(item.assignment_id for item in assignments)
    assert store.path(".stages", "randomize-confirmation.json").exists()
    assert not any(store.path("generation").iterdir())
    stage_manifest = read_stage_manifest(store.path(".stages", "randomize-confirmation.json"))
    assert set(stage_manifest.inputs) == {
        *(f"interventions/{name}" for name, _model in randomization_stage.PROMPT_VARIANT_OUTPUTS),
        ".stages/build-confirmation-variants.json",
        "discovery/hypotheses_frozen.jsonl",
        ".stages/fci-discovery.json",
    }
    assert all(
        not path.startswith(("generation/", "oracle/", "analysis/"))
        for path in stage_manifest.inputs
    )

    def forbidden_randomize(*_args, **_kwargs):
        raise AssertionError("committed assignment stage did not skip")

    monkeypatch.setattr(randomization_stage, "randomize_protocols", forbidden_randomize)
    skipped = run_confirmation_randomization_stage(config, store, force=False)
    assert skipped == result

    monkeypatch.setattr(randomization_stage, "randomize_protocols", real_randomize)
    assignment_path = store.path("interventions", "assignments.jsonl")
    canonical_assignments = assignment_path.read_bytes()
    assignment_path.write_bytes(canonical_assignments + b"\n")
    repaired = run_confirmation_randomization_stage(config, store, force=False)
    assert repaired == result
    assert assignment_path.read_bytes() == canonical_assignments

    before = {
        name: store.path("interventions", name).read_bytes()
        for name, _model in RANDOMIZATION_OUTPUTS
    }
    future = store.path("generation", "confirmation_requests.jsonl")
    future.write_text("{}\n", encoding="utf-8")
    with pytest.raises(SecAwareError) as future_error:
        run_confirmation_randomization_stage(config, store, force=True)
    assert future_error.value.message == "future confirmation artifact already exists"
    assert before == {
        name: store.path("interventions", name).read_bytes()
        for name, _model in RANDOMIZATION_OUTPUTS
    }
    future.unlink()
