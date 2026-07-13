from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from secaware.config import AppConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.run_store import RunStore
from secaware.io.transaction import ArtifactTransaction, TransactionStateError
from secaware.pipeline import jsonl_stage as jsonl_stage_module
from secaware.pipeline.jsonl_stage import (
    JsonlOutputSpec,
    execute_jsonl_stage_transaction,
)


class ProbeRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: int


def _prepared_store(tmp_path: Path) -> RunStore:
    prompts_path = tmp_path / "prompts.jsonl"
    prompts_path.write_bytes(b'{"prompt":"probe"}\n')
    config = AppConfig.model_validate(
        {
            "run": {
                "name": "jsonl-transaction-test",
                "output_dir": str(tmp_path / "run"),
            },
            "data": {"prompts_path": str(prompts_path)},
        }
    )
    store = RunStore(config)
    store.prepare()
    return store


def test_jsonl_stage_requires_at_least_one_output(tmp_path: Path) -> None:
    store = _prepared_store(tmp_path)

    with pytest.raises(SecAwareError) as exc_info:
        execute_jsonl_stage_transaction(
            store,
            stage="transaction-test",
            inputs=(store.path("inputs", "prompts.jsonl"),),
            outputs=(),
            force=True,
            build=lambda: (),
        )

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert exc_info.value.stage == "transaction-test"


def test_jsonl_stage_requires_one_record_group_per_output(tmp_path: Path) -> None:
    store = _prepared_store(tmp_path)
    one = store.path("tsg", "one.jsonl")
    two = store.path("tsg", "two.jsonl")

    with pytest.raises(SecAwareError) as exc_info:
        execute_jsonl_stage_transaction(
            store,
            stage="transaction-test",
            inputs=(store.path("inputs", "prompts.jsonl"),),
            outputs=(
                JsonlOutputSpec(one, ProbeRecord),
                JsonlOutputSpec(two, ProbeRecord),
            ),
            force=True,
            build=lambda: ((ProbeRecord(value=10),),),
        )

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert exc_info.value.stage == "transaction-test"
    assert not one.exists()
    assert not two.exists()


def test_jsonl_stage_reads_each_candidate_through_its_declared_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _prepared_store(tmp_path)
    one = store.path("tsg", "one.jsonl")
    two = store.path("tsg", "two.jsonl")
    real_read_jsonl = jsonl_stage_module.read_jsonl
    readback_models: list[type[BaseModel] | None] = []

    def observe_readback(
        path: str | Path,
        model: type[BaseModel] | None = None,
        **kwargs: object,
    ) -> list[BaseModel] | list[dict]:
        readback_models.append(model)
        return real_read_jsonl(path, model, **kwargs)

    monkeypatch.setattr(jsonl_stage_module, "read_jsonl", observe_readback)

    execute_jsonl_stage_transaction(
        store,
        stage="transaction-test",
        inputs=(store.path("inputs", "prompts.jsonl"),),
        outputs=(
            JsonlOutputSpec(one, ProbeRecord, require_nonempty=True),
            JsonlOutputSpec(two, None, require_nonempty=True),
        ),
        force=True,
        build=lambda: ((ProbeRecord(value=10),), ({"value": 20},)),
    )

    assert readback_models == [ProbeRecord, None, ProbeRecord, None]


def test_jsonl_stage_restores_all_outputs_when_second_install_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _prepared_store(tmp_path)
    one = store.path("tsg", "one.jsonl")
    two = store.path("tsg", "two.jsonl")
    one.write_bytes(b'{"old":1}\n')
    two.write_bytes(b'{"old":2}\n')
    real_install = ArtifactTransaction.install

    def fail_on_second_install(
        transaction: ArtifactTransaction,
        index: int,
        candidate: Path,
    ) -> None:
        if index == 1:
            raise TransactionStateError
        real_install(transaction, index, candidate)

    monkeypatch.setattr(ArtifactTransaction, "install", fail_on_second_install)

    with pytest.raises(SecAwareError):
        execute_jsonl_stage_transaction(
            store,
            stage="transaction-test",
            inputs=(store.path("inputs", "prompts.jsonl"),),
            outputs=(
                JsonlOutputSpec(one, ProbeRecord, require_nonempty=True),
                JsonlOutputSpec(two, ProbeRecord, require_nonempty=True),
            ),
            force=True,
            build=lambda: ((ProbeRecord(value=10),), (ProbeRecord(value=20),)),
        )

    assert one.read_bytes() == b'{"old":1}\n'
    assert two.read_bytes() == b'{"old":2}\n'


@pytest.mark.parametrize("signal_type", [KeyboardInterrupt, SystemExit])
def test_jsonl_stage_interrupt_restores_the_prior_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal_type: type[BaseException],
) -> None:
    store = _prepared_store(tmp_path)
    output = store.path("tsg", "one.jsonl")
    input_path = store.path("inputs", "prompts.jsonl")
    spec = JsonlOutputSpec(output, ProbeRecord, require_nonempty=True)
    execute_jsonl_stage_transaction(
        store,
        stage="transaction-test",
        inputs=(input_path,),
        outputs=(spec,),
        force=True,
        build=lambda: ((ProbeRecord(value=10),),),
    )
    manifest_path = store.path(".stages", "transaction-test.json")
    output_before = output.read_bytes()
    manifest_before = manifest_path.read_bytes()
    signal = signal_type("private-transaction-interrupt")

    def interrupt_install(
        transaction: ArtifactTransaction,
        index: int,
        candidate: Path,
    ) -> None:
        del transaction, index, candidate
        raise signal

    monkeypatch.setattr(ArtifactTransaction, "install", interrupt_install)

    with pytest.raises(signal_type) as exc_info:
        execute_jsonl_stage_transaction(
            store,
            stage="transaction-test",
            inputs=(input_path,),
            outputs=(spec,),
            force=True,
            build=lambda: ((ProbeRecord(value=20),),),
        )

    assert exc_info.value is signal
    assert output.read_bytes() == output_before
    assert manifest_path.read_bytes() == manifest_before


def test_jsonl_stage_commits_manifest_only_after_output_sealing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _prepared_store(tmp_path)
    output = store.path("tsg", "one.jsonl")
    sealed = False
    real_seal = store.seal_stage_outputs
    real_record = store.record_stage

    def observe_seal(stage: str, outputs: list[Path]) -> None:
        nonlocal sealed
        real_seal(stage, outputs)
        sealed = True

    def observe_record(*args: object, **kwargs: object) -> None:
        assert sealed
        real_record(*args, **kwargs)

    monkeypatch.setattr(store, "seal_stage_outputs", observe_seal)
    monkeypatch.setattr(store, "record_stage", observe_record)

    execute_jsonl_stage_transaction(
        store,
        stage="transaction-test",
        inputs=(store.path("inputs", "prompts.jsonl"),),
        outputs=(JsonlOutputSpec(output, ProbeRecord, require_nonempty=True),),
        force=True,
        build=lambda: ((ProbeRecord(value=10),),),
    )

    assert store.path(".stages", "transaction-test.json").exists()
