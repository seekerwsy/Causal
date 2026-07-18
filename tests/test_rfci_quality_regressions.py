from __future__ import annotations

import base64
import hashlib
from importlib.machinery import ModuleSpec
import inspect
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from secaware.config import RFCIConfig
from secaware.errors import SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import PAGRecord, PAGRunKind
from secaware.schema.outcomes import RFCICapabilityRecord, RFCISensitivityResult

from test_rfci_adapter import (
    PINNED_COMMIT,
    PINNED_JAR_SHA256,
    _capability,
    _config,
    _rows,
    _table,
)


def _record_row(relative_path: str, payload: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
    return f"{relative_path},sha256={digest},{len(payload)}\n"


def _inactive_capability(status: str) -> RFCICapabilityRecord:
    return RFCICapabilityRecord(
        schema_version="1.0",
        available=False,
        status=status,
        requires_java=True,
        python_version="3.12.9",
        java_major=None,
        jpype_version=None,
        py_tetrad_commit=None,
        tetrad_jar_sha256=None,
        reason_code="disabled" if status == "disabled" else "jpype_missing",
    )


class _Poison:
    def __getattribute__(self, _name: str) -> object:
        raise AssertionError("disabled RFCI touched an input")

    def __iter__(self) -> object:
        raise AssertionError("disabled RFCI iterated rows")


def _available_probe(monkeypatch: pytest.MonkeyPatch, *, origins: dict[str, Path]) -> object:
    from secaware.discovery import rfci_backend

    monkeypatch.setattr(rfci_backend, "_runtime_python_version", lambda: "3.12.9")
    monkeypatch.setattr(
        rfci_backend.importlib.util,
        "find_spec",
        lambda name: ModuleSpec(name, loader=None, origin=str(origins[name])),
    )
    monkeypatch.setattr(rfci_backend.importlib.metadata, "version", lambda _name: "1.7.1")
    monkeypatch.setattr(
        rfci_backend,
        "_inspect_py_tetrad_installation",
        lambda: (PINNED_COMMIT, PINNED_JAR_SHA256),
    )
    monkeypatch.setattr(rfci_backend, "_detect_java_major", lambda: 21)
    return rfci_backend


def _forged_pag(*, backend: str = "forged_backend", config: RFCIConfig | None = None) -> PAGRecord:
    table = _table()
    checked_config = _config() if config is None else config
    return PAGRecord.from_content(
        run_kind=PAGRunKind.RFCI_SENSITIVITY,
        table_id=table.table_id,
        backend=backend,
        backend_version=PINNED_COMMIT,
        ci_test="gsq",
        config_sha256=canonical_sha256(checked_config.model_dump(mode="json")),
        background_knowledge_sha256="0" * 64,
        variable_ids=tuple(item.variable_id for item in table.variables),
        edges=(),
    )


def test_runtime_probe_rejects_shadow_module_origins(monkeypatch: pytest.MonkeyPatch) -> None:
    origins = {
        "jpype": Path("C:/attacker/jpype/__init__.py"),
        "pytetrad": Path("C:/attacker/pytetrad/__init__.py"),
    }
    backend = _available_probe(monkeypatch, origins=origins)

    capability = backend.detect_rfci_capability(RFCIConfig(enabled=True))

    assert capability.available is False
    assert capability.reason_code == "runtime_provenance_invalid"


def test_distribution_authenticator_rejects_modified_or_missing_record_hash(
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend

    assert hasattr(rfci_backend, "_authenticate_distribution")
    authenticate = rfci_backend._authenticate_distribution
    package = tmp_path / "site" / "pytetrad"
    package.mkdir(parents=True)
    source = package / "__init__.py"
    source.write_bytes(b"trusted = True\n")
    expected = hashlib.sha256(source.read_bytes()).digest()
    encoded = base64.urlsafe_b64encode(expected).rstrip(b"=").decode("ascii")
    record = tmp_path / "site" / "py_tetrad-1.dist-info" / "RECORD"
    record.parent.mkdir()
    record.write_text(
        f"pytetrad/__init__.py,sha256={encoded},{source.stat().st_size}\n", encoding="utf-8"
    )
    source.write_bytes(b"trusted = False\n")

    with pytest.raises(SecAwareError):
        authenticate(
            distribution_name="py-tetrad",
            module_name="pytetrad",
            expected_origin=source,
            required_relative_paths=("pytetrad/__init__.py",),
            distribution_root=tmp_path / "site",
            record_path=record,
        )


@pytest.mark.parametrize("mode", ("source", "orphan_cache"))
def test_distribution_authenticator_rejects_unrecorded_importable_file(
    tmp_path: Path,
    mode: str,
) -> None:
    from secaware.discovery import rfci_backend

    root = tmp_path / "site"
    package = root / "pytetrad"
    package.mkdir(parents=True)
    source = package / "__init__.py"
    source.write_bytes(b"trusted = True\n")
    if mode == "source":
        (package / "shadow.py").write_bytes(b"trusted = False\n")
    else:
        cache = package / "__pycache__" / "ghost.cpython-312.pyc"
        cache.parent.mkdir()
        cache.write_bytes(b"untrusted bytecode")
    record = root / "py_tetrad-1.dist-info" / "RECORD"
    record.parent.mkdir()
    record.write_text(_record_row("pytetrad/__init__.py", source.read_bytes()), encoding="utf-8")

    with pytest.raises(SecAwareError):
        rfci_backend._authenticate_distribution(
            distribution_name="py-tetrad",
            module_name="pytetrad",
            expected_origin=source,
            required_relative_paths=("pytetrad/__init__.py",),
            distribution_root=root,
            record_path=record,
        )


def test_distribution_authenticator_accepts_complete_recorded_package(tmp_path: Path) -> None:
    from secaware.discovery import rfci_backend

    root = tmp_path / "site"
    package = root / "pytetrad"
    package.mkdir(parents=True)
    source = package / "__init__.py"
    module = package / "search.py"
    source.write_bytes(b"trusted = True\n")
    module.write_bytes(b"search = True\n")
    cache = package / "__pycache__" / "search.cpython-312.pyc"
    cache.parent.mkdir()
    cache.write_bytes(b"normal generated cache")
    record = root / "py_tetrad-1.dist-info" / "RECORD"
    record.parent.mkdir()
    record.write_text(
        _record_row("pytetrad/__init__.py", source.read_bytes())
        + _record_row("pytetrad/search.py", module.read_bytes()),
        encoding="utf-8",
    )

    evidence = rfci_backend._authenticate_distribution(
        distribution_name="py-tetrad",
        module_name="pytetrad",
        expected_origin=source,
        required_relative_paths=("pytetrad/__init__.py", "pytetrad/search.py"),
        distribution_root=root,
        record_path=record,
    )

    assert evidence.module_origin == str(source.resolve())


@pytest.mark.parametrize("flags", (("-I",), ("-I", "-B")), ids=("isolated", "isolated-no-write"))
def test_python_isolation_flags_still_read_existing_source_backed_bytecode(
    tmp_path: Path,
    flags: tuple[str, ...],
) -> None:
    source = tmp_path / "probe.py"
    trusted = b"VALUE = 'trusted'   \n"
    unchecked = b"VALUE = 'unchecked' \n"
    assert len(trusted) == len(unchecked)
    fixed_time = 1_700_000_000
    source.write_bytes(unchecked)
    os.utime(source, (fixed_time, fixed_time))
    py_compile.compile(
        str(source),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
    )
    source.write_bytes(trusted)
    os.utime(source, (fixed_time, fixed_time))

    completed = subprocess.run(
        (
            sys.executable,
            *flags,
            "-c",
            "import sys;sys.path.insert(0,sys.argv[1]);import probe;sys.stdout.write(probe.VALUE)",
            str(tmp_path),
        ),
        check=True,
        capture_output=True,
        timeout=5.0,
    )

    assert completed.stdout == b"unchecked"


def test_rfci_worker_argv_creates_fresh_private_cache_prefix(tmp_path: Path) -> None:
    from secaware.discovery import rfci_backend

    job_root = tmp_path / "job"
    job_root.mkdir()
    job_path = job_root / "job.json"
    job_path.write_bytes(b"{}")

    argv = rfci_backend._build_rfci_worker_argv(job_path)

    cache = job_root / "cache"
    assert cache.is_dir()
    assert not cache.is_symlink()
    assert tuple(cache.iterdir()) == ()
    assert cache.resolve().parent == job_root.resolve()
    assert argv == (
        sys.executable,
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={cache.resolve()}",
        "-m",
        "secaware.discovery._rfci_worker",
        str(job_path.resolve()),
    )


@pytest.mark.parametrize(
    ("dont_write_bytecode", "prefix_kind"),
    ((False, "exact"), (True, "none"), (True, "wrong")),
)
def test_rfci_worker_rejects_inexact_python_cache_runtime_before_decoding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    dont_write_bytecode: bool,
    prefix_kind: str,
) -> None:
    from secaware.discovery import rfci_backend

    job_root = tmp_path / "job"
    cache = job_root / "cache"
    cache.mkdir(parents=True)
    job_path = job_root / "job.json"
    job_path.write_bytes(b"{}")
    prefix = {"exact": str(cache.resolve()), "none": None, "wrong": str(tmp_path / "wrong")}
    monkeypatch.setattr(sys, "dont_write_bytecode", dont_write_bytecode)
    monkeypatch.setattr(sys, "pycache_prefix", prefix[prefix_kind])
    monkeypatch.setattr(
        rfci_backend,
        "_decode_job",
        lambda _payload: pytest.fail("invalid Python cache runtime reached job decoding"),
    )

    with pytest.raises(ValueError):
        rfci_backend._execute_worker_job(job_path)


def test_installed_module_authentication_requires_exact_single_package_location(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend

    root = tmp_path / "site"
    source = root / "pytetrad" / "__init__.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"trusted = True\n")
    record = root / "py_tetrad-1.dist-info" / "RECORD"
    record.parent.mkdir()
    record.write_text(_record_row("pytetrad/__init__.py", source.read_bytes()), encoding="utf-8")

    class Distribution:
        files = (Path("py_tetrad-1.dist-info/RECORD"), Path("pytetrad/__init__.py"))

        def locate_file(self, item: object) -> Path:
            return root / Path(str(item))

    spec = ModuleSpec("pytetrad", loader=None, origin=str(source))
    spec.submodule_search_locations = [str(tmp_path / "attacker")]
    monkeypatch.setattr(
        rfci_backend.importlib.metadata, "distribution", lambda _name: Distribution()
    )

    with pytest.raises(SecAwareError):
        rfci_backend._authenticate_installed_module("py-tetrad", "pytetrad", spec)


def test_recorded_metadata_authentication_never_uses_unbounded_read_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend

    root = tmp_path / "site"
    metadata = root / "py_tetrad-1.dist-info" / "direct_url.json"
    metadata.parent.mkdir(parents=True)
    payload = b'{"url":"trusted"}'
    metadata.write_bytes(payload)
    record = metadata.parent / "RECORD"
    relative = "py_tetrad-1.dist-info/direct_url.json"
    record.write_text(_record_row(relative, payload), encoding="utf-8")
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path.resolve() == record.resolve():
            raise AssertionError("RECORD must be read with an explicit byte limit")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)

    checked_path, _sha256, size = rfci_backend._authenticate_recorded_metadata_file(
        root=root,
        record_path=record,
        relative_path=relative,
        size_limit=rfci_backend._MAX_DIRECT_URL_BYTES,
    )

    assert checked_path == metadata.resolve()
    assert size == len(payload)


@pytest.mark.parametrize("mode", ("missing_hash", "path_escape", "symlink"))
def test_distribution_authenticator_rejects_untrusted_record_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
) -> None:
    from secaware.discovery import rfci_backend

    root = tmp_path / "site"
    package = root / "pytetrad"
    package.mkdir(parents=True)
    source = package / "__init__.py"
    source.write_bytes(b"trusted = True\n")
    record = root / "py_tetrad-1.dist-info" / "RECORD"
    record.parent.mkdir()
    required = "pytetrad/__init__.py"
    if mode == "missing_hash":
        record.write_text(f"{required},,{source.stat().st_size}\n", encoding="utf-8")
    elif mode == "path_escape":
        required = "../pytetrad/__init__.py"
        record.write_text(_record_row(required, source.read_bytes()), encoding="utf-8")
    else:
        target = root / "real.py"
        target.write_bytes(source.read_bytes())
        source.unlink()
        try:
            source.symlink_to(target)
        except OSError:
            source.write_bytes(target.read_bytes())
            original = rfci_backend._path_has_symlink
            monkeypatch.setattr(
                rfci_backend,
                "_path_has_symlink",
                lambda path, checked_root: (
                    Path(path) == source or original(Path(path), Path(checked_root))
                ),
            )
        record.write_text(_record_row(required, target.read_bytes()), encoding="utf-8")

    with pytest.raises(SecAwareError):
        rfci_backend._authenticate_distribution(
            distribution_name="py-tetrad",
            module_name="pytetrad",
            expected_origin=source,
            required_relative_paths=(required,),
            distribution_root=root,
            record_path=record,
        )


def test_py_tetrad_direct_url_is_hashed_into_private_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend

    root = tmp_path / "site"
    package = root / "pytetrad"
    jar = package / "resources" / "tetrad-current.jar"
    direct_url = root / "py_tetrad-1.dist-info" / "direct_url.json"
    record = direct_url.parent / "RECORD"
    jar.parent.mkdir(parents=True)
    direct_url.parent.mkdir(parents=True)
    jar.write_bytes(b"authenticated jar")
    direct_payload = json.dumps(
        {
            "url": rfci_backend._PY_TETRAD_URL,
            "vcs_info": {"commit_id": PINNED_COMMIT, "vcs": "git"},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    direct_url.write_bytes(direct_payload)
    record.write_text(
        _record_row("py_tetrad-1.dist-info/direct_url.json", direct_payload)
        + _record_row("pytetrad/resources/tetrad-current.jar", jar.read_bytes()),
        encoding="utf-8",
    )

    class Distribution:
        files = (
            Path("py_tetrad-1.dist-info/RECORD"),
            Path("py_tetrad-1.dist-info/direct_url.json"),
            Path("pytetrad/resources/tetrad-current.jar"),
        )

        def locate_file(self, item: object) -> Path:
            return root / Path(str(item))

    monkeypatch.setattr(
        rfci_backend.importlib.metadata, "distribution", lambda _name: Distribution()
    )

    evidence = rfci_backend._inspect_py_tetrad_installation_evidence()

    assert evidence.direct_url_path == str(direct_url.resolve())
    assert evidence.direct_url_sha256 == hashlib.sha256(direct_payload).hexdigest()
    assert evidence.direct_url_size == len(direct_payload)
    assert evidence.jar_path == str(jar.resolve())
    direct_url.write_bytes(direct_payload + b" ")
    assert rfci_backend._inspect_py_tetrad_installation() == (None, None)


def test_collect_runtime_evidence_accepts_complete_synthetic_distributions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend

    root = tmp_path / "site"
    jpype_source = root / "jpype" / "__init__.py"
    jpype_native = root / "_jpype.pyd"
    pytetrad_source = root / "pytetrad" / "__init__.py"
    jar = root / "pytetrad" / "resources" / "tetrad-current.jar"
    for path, payload in (
        (jpype_source, b"jpype source"),
        (jpype_native, b"jpype native"),
        (pytetrad_source, b"pytetrad source"),
        (jar, b"synthetic tetrad jar"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    direct_payload = json.dumps(
        {
            "url": rfci_backend._PY_TETRAD_URL,
            "vcs_info": {"commit_id": PINNED_COMMIT, "vcs": "git"},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    direct_url = root / "py_tetrad-1.dist-info" / "direct_url.json"
    direct_url.parent.mkdir()
    direct_url.write_bytes(direct_payload)
    jpype_record = root / "JPype1-1.dist-info" / "RECORD"
    jpype_record.parent.mkdir()
    jpype_record.write_text(
        _record_row("jpype/__init__.py", jpype_source.read_bytes())
        + _record_row("_jpype.pyd", jpype_native.read_bytes()),
        encoding="utf-8",
    )
    pytetrad_record = direct_url.parent / "RECORD"
    pytetrad_record.write_text(
        _record_row("pytetrad/__init__.py", pytetrad_source.read_bytes())
        + _record_row("pytetrad/resources/tetrad-current.jar", jar.read_bytes())
        + _record_row("py_tetrad-1.dist-info/direct_url.json", direct_payload),
        encoding="utf-8",
    )

    class Distribution:
        def __init__(self, files: tuple[str, ...]) -> None:
            self.files = tuple(Path(item) for item in files)

        def locate_file(self, item: object) -> Path:
            return root / Path(str(item))

    distributions = {
        "JPype1": Distribution(("JPype1-1.dist-info/RECORD", "jpype/__init__.py", "_jpype.pyd")),
        "py-tetrad": Distribution(
            (
                "py_tetrad-1.dist-info/RECORD",
                "py_tetrad-1.dist-info/direct_url.json",
                "pytetrad/__init__.py",
                "pytetrad/resources/tetrad-current.jar",
            )
        ),
    }
    specs = {
        "jpype": ModuleSpec("jpype", loader=None, origin=str(jpype_source)),
        "pytetrad": ModuleSpec("pytetrad", loader=None, origin=str(pytetrad_source)),
    }
    for name, spec in specs.items():
        spec.submodule_search_locations = [str(root / name)]
    java = rfci_backend._JavaRuntimeEvidence(
        executable=str(tmp_path / "jdk" / "bin" / "java.exe"),
        home=str(tmp_path / "jdk"),
        jvm_library=str(tmp_path / "jdk" / "bin" / "server" / "jvm.dll"),
        executable_sha256="a" * 64,
        jvm_library_sha256="b" * 64,
        major=21,
    )
    jar_sha256 = hashlib.sha256(jar.read_bytes()).hexdigest()
    monkeypatch.setattr(rfci_backend, "TETRAD_JAR_SHA256", jar_sha256)
    monkeypatch.setattr(rfci_backend, "_runtime_python_version", lambda: "3.12.9")
    monkeypatch.setattr(rfci_backend.importlib.util, "find_spec", specs.get)
    monkeypatch.setattr(
        rfci_backend.importlib.metadata,
        "distribution",
        distributions.__getitem__,
    )
    monkeypatch.setattr(rfci_backend.importlib.metadata, "version", lambda _name: "1.7.1")
    monkeypatch.setattr(rfci_backend, "_select_java_runtime", lambda: java)
    monkeypatch.setattr(rfci_backend, "_probe_java_runtime", lambda selected: selected)

    evidence = rfci_backend._collect_runtime_evidence(_config())

    assert evidence.capability.available is True
    assert (
        evidence.py_tetrad_installation.direct_url_sha256
        == hashlib.sha256(direct_payload).hexdigest()
    )
    assert evidence.py_tetrad_installation.jar_sha256 == jar_sha256
    assert evidence.jpype.manifest_sha256 != evidence.pytetrad.manifest_sha256


@pytest.mark.parametrize("mode", ("noncanonical", "oversized"))
def test_worker_job_decoder_rejects_noncanonical_or_oversized_payload(mode: str) -> None:
    from secaware.discovery import rfci_backend

    payload = b"{} " if mode == "noncanonical" else b"x" * (rfci_backend._MAX_JOB_BYTES + 1)
    with pytest.raises((ValueError, SecAwareError)):
        rfci_backend._decode_job(payload)


def test_worker_rejects_parent_evidence_mismatch_before_import(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend

    cache = tmp_path / "cache"
    cache.mkdir()
    job_path = tmp_path / "job.json"
    job_path.write_bytes(b"{}")
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    monkeypatch.setattr(sys, "pycache_prefix", str(cache.resolve()))
    expected = object()
    monkeypatch.setattr(
        rfci_backend,
        "_decode_job",
        lambda _payload: SimpleNamespace(config=_config(), evidence=expected),
    )
    monkeypatch.setattr(rfci_backend, "_collect_runtime_evidence", lambda _config: object())
    monkeypatch.setattr(
        rfci_backend,
        "_sanitize_worker_import_path",
        lambda _evidence: pytest.fail("mismatched evidence must stop before import path mutation"),
    )

    with pytest.raises(ValueError):
        rfci_backend._execute_worker_job(job_path)


def test_disabled_run_returns_before_touching_any_analysis_input() -> None:
    from secaware.discovery.rfci_backend import run_rfci_sensitivity

    result = run_rfci_sensitivity(
        _Poison(),  # type: ignore[arg-type]
        _Poison(),  # type: ignore[arg-type]
        _Poison(),  # type: ignore[arg-type]
        RFCIConfig(),
    )

    assert result.capability.status == "disabled"
    assert result.pag is None


def test_public_rfci_api_exposes_no_worker_factory_or_capability_injection() -> None:
    from secaware.discovery import rfci_backend

    parameters = inspect.signature(rfci_backend.run_rfci_sensitivity).parameters
    assert set(parameters) == {"table", "rows", "knowledge", "config"}
    assert "SpawnedRFCIRunner" not in rfci_backend.__all__
    assert not hasattr(rfci_backend, "SpawnedRFCIRunner")


def test_private_fake_adapter_cannot_mint_a_production_result() -> None:
    from secaware.discovery import rfci_backend

    assert hasattr(rfci_backend, "_run_test_rfci_adapter")
    fake_pag = rfci_backend._run_test_rfci_adapter(
        _table(),
        _rows(_table()),
        _config(),
    )
    assert fake_pag.backend == "test_rfci_fake_v1"
    with pytest.raises(ValidationError):
        RFCISensitivityResult(capability=_capability(), pag=fake_pag)


@pytest.mark.parametrize(
    "capability",
    (
        _capability(jpype_version="9.9"),
        _capability(tetrad_jar_sha256="f" * 64),
    ),
)
def test_result_rejects_non_authoritative_available_capability(
    capability: RFCICapabilityRecord,
) -> None:
    with pytest.raises(ValidationError):
        RFCISensitivityResult(capability=capability, pag=_forged_pag(backend="py_tetrad_rfci_v2"))


def test_result_rejects_nonproduction_backend_even_with_recomputed_pag_id() -> None:
    with pytest.raises(ValidationError):
        RFCISensitivityResult(capability=_capability(), pag=_forged_pag())


def test_public_relation_validator_rejects_recomputed_config_provenance() -> None:
    from secaware.causal.background import build_background_knowledge
    from secaware.discovery import rfci_backend

    assert hasattr(rfci_backend, "validate_rfci_sensitivity_result")
    table = _table()
    knowledge = build_background_knowledge(table)
    config = _config(alpha=0.01)
    wrong_config = _config(alpha=0.02)
    pag = PAGRecord.from_content(
        run_kind=PAGRunKind.RFCI_SENSITIVITY,
        table_id=table.table_id,
        backend="py_tetrad_rfci_v2",
        backend_version=PINNED_COMMIT,
        ci_test="gsq",
        config_sha256=canonical_sha256(wrong_config.model_dump(mode="json")),
        background_knowledge_sha256=knowledge.knowledge_sha256,
        variable_ids=tuple(item.variable_id for item in table.variables),
        edges=(),
    )
    result = RFCISensitivityResult(capability=_capability(), pag=pag)

    with pytest.raises(SecAwareError):
        rfci_backend.validate_rfci_sensitivity_result(result, table, knowledge, config)


def test_relation_validator_rejects_disabled_config_with_available_pag() -> None:
    from secaware.causal.background import build_background_knowledge
    from secaware.discovery import rfci_backend

    table = _table()
    knowledge = build_background_knowledge(table)
    config = RFCIConfig()
    pag = PAGRecord.from_content(
        run_kind=PAGRunKind.RFCI_SENSITIVITY,
        table_id=table.table_id,
        backend="py_tetrad_rfci_v2",
        backend_version=PINNED_COMMIT,
        ci_test="gsq",
        config_sha256=canonical_sha256(config.model_dump(mode="json")),
        background_knowledge_sha256=knowledge.knowledge_sha256,
        variable_ids=tuple(item.variable_id for item in table.variables),
        edges=(),
    )
    result = RFCISensitivityResult(capability=_capability(), pag=pag)

    with pytest.raises(SecAwareError):
        rfci_backend.validate_rfci_sensitivity_result(result, table, knowledge, config)


def test_relation_validator_rejects_enabled_config_with_disabled_capability() -> None:
    from secaware.causal.background import build_background_knowledge
    from secaware.discovery import rfci_backend

    table = _table()
    knowledge = build_background_knowledge(table)
    result = RFCISensitivityResult(capability=_inactive_capability("disabled"), pag=None)

    with pytest.raises(SecAwareError):
        rfci_backend.validate_rfci_sensitivity_result(result, table, knowledge, _config())


@pytest.mark.parametrize(
    ("config", "status"),
    ((RFCIConfig(), "disabled"), (_config(), "unavailable")),
    ids=("disabled-disabled", "enabled-unavailable"),
)
def test_relation_validator_accepts_matching_inactive_state(
    config: RFCIConfig,
    status: str,
) -> None:
    from secaware.causal.background import build_background_knowledge
    from secaware.discovery import rfci_backend

    table = _table()
    knowledge = build_background_knowledge(table)
    result = RFCISensitivityResult(capability=_inactive_capability(status), pag=None)

    assert rfci_backend.validate_rfci_sensitivity_result(result, table, knowledge, config) == result


def test_available_capability_validation_requires_enabled_config() -> None:
    from secaware.discovery import rfci_backend

    with pytest.raises(ValueError):
        rfci_backend._validate_available_capability(_capability(), RFCIConfig())


def test_rfci_production_source_contains_no_pickle_or_multiprocessing_transport() -> None:
    from secaware.discovery import rfci_backend

    source = inspect.getsource(rfci_backend)
    assert "ForkingPickler" not in source
    assert "multiprocessing" not in source
    assert ".send_bytes(" not in source
    assert ".recv_bytes(" not in source


def test_raw_matrix_transport_rejects_content_tamper(tmp_path: Path) -> None:
    from secaware.discovery import rfci_backend

    assert hasattr(rfci_backend, "_write_matrix_transport")
    assert hasattr(rfci_backend, "_read_matrix_transport")
    import numpy as np

    matrix = np.asarray(((0, 1), (1, 0)), dtype=np.int64)
    lease = rfci_backend._write_matrix_transport(matrix, tmp_path)
    with lease.path.open("r+b") as handle:
        handle.seek(0)
        handle.write(b"\xff")
    with pytest.raises(SecAwareError):
        rfci_backend._read_matrix_transport(lease)
    lease.close()


def test_raw_matrix_transport_binds_shape_length_and_lease_cleanup(tmp_path: Path) -> None:
    from secaware.discovery import rfci_backend
    import numpy as np

    matrix = np.asarray(((0, 1), (1, 0)), dtype=np.int64)
    lease = rfci_backend._write_matrix_transport(matrix, tmp_path)
    tampered = lease.record.model_copy(update={"rows": 3})
    with pytest.raises(SecAwareError):
        rfci_backend._read_matrix_transport(tampered, trusted_root=tmp_path)
    path = lease.path
    lease.close()
    assert not path.exists()


def test_matrix_transport_never_returns_same_length_replacement_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend
    import numpy as np

    matrix = np.asarray(((0, 1), (1, 0)), dtype=np.int64)
    replacement = np.asarray(((9, 9), (9, 9)), dtype=np.int64).tobytes(order="C")
    lease = rfci_backend._write_matrix_transport(matrix, tmp_path)
    original_hash = rfci_backend._hash_regular_file

    def hash_then_replace(path: Path, *, limit: int) -> tuple[str, int]:
        result = original_hash(path, limit=limit)
        replacement_path = tmp_path / "replacement.raw"
        replacement_path.write_bytes(replacement)
        os.replace(replacement_path, lease.path)
        return result

    monkeypatch.setattr(rfci_backend, "_hash_regular_file", hash_then_replace)

    returned = rfci_backend._read_matrix_transport(lease.record, trusted_root=tmp_path)

    assert hashlib.sha256(returned.tobytes(order="C")).hexdigest() == lease.record.sha256


def test_matrix_transport_reads_and_verifies_one_descriptor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend
    import numpy as np

    matrix = np.asarray(((0, 1), (1, 0)), dtype=np.int64)
    lease = rfci_backend._write_matrix_transport(matrix, tmp_path)
    original_open = os.open
    original_fstat = os.fstat
    original_read_bytes = Path.read_bytes
    opened: list[int] = []
    stated: list[int] = []

    def tracked_open(path: object, flags: int, *args: object) -> int:
        descriptor = original_open(path, flags, *args)
        if Path(path) == lease.path:
            opened.append(descriptor)
        return descriptor

    def tracked_fstat(descriptor: int) -> os.stat_result:
        if descriptor in opened:
            stated.append(descriptor)
        return original_fstat(descriptor)

    def guarded_read_bytes(path: Path) -> bytes:
        if path.resolve() == lease.path.resolve():
            raise AssertionError("matrix transport must not reopen by path")
        return original_read_bytes(path)

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(os, "fstat", tracked_fstat)
    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)
    try:
        returned = rfci_backend._read_matrix_transport(lease, trusted_root=tmp_path)
    finally:
        lease.close()

    assert hashlib.sha256(returned.tobytes(order="C")).hexdigest() == lease.record.sha256
    assert len(opened) == 1
    assert len(stated) >= 2
    assert set(stated) == set(opened)


@pytest.mark.parametrize(
    ("mode", "expected_kind"),
    (
        ("oversize", "invalid_output"),
        ("partial", "invalid_output"),
        ("timeout", "timeout"),
        ("crash", "backend_failure"),
    ),
)
def test_fixed_subprocess_transport_rejects_failure_and_cleans_up(
    tmp_path: Path,
    mode: str,
    expected_kind: str,
) -> None:
    import secaware

    assert hasattr(secaware, "process_isolation")
    process_isolation = secaware.process_isolation
    marker = tmp_path / "marker"
    scripts = {
        "oversize": "import sys;sys.stdout.buffer.write(b'x'*4097)",
        "partial": "import sys;sys.stdout.buffer.write(b'{')",
        "timeout": "import time;time.sleep(30)",
        "crash": "import os;os._exit(7)",
    }
    with pytest.raises(SecAwareError) as exc_info:
        process_isolation.run_isolated_process(
            (sys.executable, "-I", "-c", scripts[mode]),
            cwd=tmp_path,
            environment={"PATH": "", "PYTHONUTF8": "1"},
            timeout_seconds=0.1 if mode == "timeout" else 2.0,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
            require_canonical_json=True,
        )
    assert exc_info.value.details == {"failure_kind": expected_kind}
    assert not marker.exists()


@pytest.mark.parametrize("stream_name", ("stdout", "stderr"))
def test_isolated_process_overflow_while_child_alive_is_invalid_output_and_reaped(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stream_name: str,
) -> None:
    import secaware

    process_isolation = secaware.process_isolation
    processes: list[subprocess.Popen[bytes]] = []
    readers: list[object] = []
    real_popen = process_isolation.subprocess.Popen
    real_thread = process_isolation.threading.Thread

    def tracked_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    def tracked_thread(*args: object, **kwargs: object) -> object:
        reader = real_thread(*args, **kwargs)
        readers.append(reader)
        return reader

    monkeypatch.setattr(process_isolation.subprocess, "Popen", tracked_popen)
    monkeypatch.setattr(process_isolation.threading, "Thread", tracked_thread)
    script = (
        "import sys,time;"
        f"stream=sys.{stream_name}.buffer;"
        "stream.write(b'x'*8192);stream.flush();time.sleep(30)"
    )

    with pytest.raises(SecAwareError) as exc_info:
        process_isolation.run_isolated_process(
            (sys.executable, "-I", "-c", script),
            cwd=tmp_path,
            environment={"PATH": "", "PYTHONUTF8": "1"},
            timeout_seconds=5.0,
            max_stdout_bytes=4096,
            max_stderr_bytes=4096,
            require_canonical_json=False,
        )

    assert exc_info.value.details == {"failure_kind": "invalid_output"}
    assert len(processes) == 1 and processes[0].poll() is not None
    assert len(readers) == 2 and all(not reader.is_alive() for reader in readers)


def test_isolated_process_reaps_descendant_holding_stdout_open(tmp_path: Path) -> None:
    import secaware

    script = (
        "import subprocess,sys;"
        "subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(30)']);"
        "sys.stdout.write('{\"ok\":true}');sys.stdout.flush()"
    )
    started = time.monotonic()
    result = secaware.process_isolation.run_isolated_process(
        (sys.executable, "-I", "-c", script),
        cwd=tmp_path,
        environment={"PATH": "", "PYTHONUTF8": "1"},
        timeout_seconds=5.0,
        max_stdout_bytes=4096,
        max_stderr_bytes=4096,
        require_canonical_json=True,
    )

    assert result.stdout == b'{"ok":true}'
    assert time.monotonic() - started < 5.0


def test_java_selection_rejects_path_and_java_home_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from secaware.discovery import rfci_backend

    assert hasattr(rfci_backend, "_select_java_runtime")
    path_home = tmp_path / "path-jdk"
    env_home = tmp_path / "env-jdk"
    suffix = ".exe" if os.name == "nt" else ""
    for home in (path_home, env_home):
        executable = home / "bin" / f"java{suffix}"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"java")
    monkeypatch.setenv("JAVA_HOME", str(env_home))
    monkeypatch.setattr(
        rfci_backend.shutil, "which", lambda _name: str(path_home / "bin" / f"java{suffix}")
    )

    with pytest.raises(SecAwareError):
        rfci_backend._select_java_runtime()


def test_java_probe_launch_uses_tree_owner_before_resume() -> None:
    from secaware.discovery import rfci_backend

    source = inspect.getsource(rfci_backend._probe_java_runtime)
    assert "taskkill" not in source
    assert "run_isolated_process" in source


def test_worker_starts_exact_authenticated_jvm_and_jar_paths() -> None:
    from secaware.discovery import rfci_backend

    source = inspect.getsource(rfci_backend._execute_worker_job)
    assert "actual.java.jvm_library" in source
    assert "actual.py_tetrad_installation.jar_path" in source
    assert "jpype.getDefaultJVMPath" not in source


def test_rfci_exports_are_consistent() -> None:
    import secaware.discovery as discovery
    import secaware.schema as schema
    from secaware.schema import outcomes

    assert "RFCISensitivityResult" in outcomes.__all__
    assert schema.RFCISensitivityResult is RFCISensitivityResult
    assert schema.RFCICapabilityRecord is RFCICapabilityRecord
    assert discovery.run_rfci_sensitivity is not None
    assert discovery.validate_rfci_sensitivity_result is not None


def test_discovery_rfci_exports_are_lazy_after_freeze_import_in_fresh_python() -> None:
    script = """
import subprocess
import sys

def forbidden_process(*_args, **_kwargs):
    raise AssertionError("minimum RFCI import started an external process")

from secaware.causal.freeze import revalidate_frozen_hypothesis
assert callable(revalidate_frozen_hypothesis)
assert "secaware.discovery.rfci_backend" not in sys.modules
subprocess.Popen = forbidden_process
from secaware.discovery import (
    detect_rfci_capability,
    run_rfci_sensitivity,
    validate_rfci_sensitivity_result,
)
assert callable(detect_rfci_capability)
assert callable(run_rfci_sensitivity)
assert callable(validate_rfci_sensitivity_result)
assert "jpype" not in sys.modules
assert "pytetrad" not in sys.modules
"""
    completed = subprocess.run(
        (sys.executable, "-I", "-c", script),
        capture_output=True,
        timeout=30.0,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
