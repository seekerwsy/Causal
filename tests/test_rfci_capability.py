from __future__ import annotations

import builtins
from copy import deepcopy

import pytest
from pydantic import ValidationError


PINNED_COMMIT = "a30707264aa4363a23ac5f136a70bbdd62212f07"
PINNED_JAR_SHA256 = "3c898047c26a909495925d3e50264150f58ee57cd5b48d95683c45e3ab0e17f4"


def _enable_probe(monkeypatch: pytest.MonkeyPatch) -> object:
    from secaware.discovery import rfci_backend

    monkeypatch.setattr(rfci_backend, "_runtime_python_version", lambda: "3.12.9")
    monkeypatch.setattr(
        rfci_backend.importlib.util,
        "find_spec",
        lambda name: object() if name in {"jpype", "pytetrad"} else None,
    )
    monkeypatch.setattr(
        rfci_backend.importlib.metadata,
        "version",
        lambda name: "1.7.1" if name == "JPype1" else "0.1.2",
    )
    monkeypatch.setattr(
        rfci_backend,
        "_inspect_py_tetrad_installation",
        lambda: (PINNED_COMMIT, PINNED_JAR_SHA256),
    )
    monkeypatch.setattr(rfci_backend, "_detect_java_major", lambda: 21)
    return rfci_backend


def test_default_rfci_config_is_strict_frozen_bounded_and_disabled() -> None:
    from secaware.config import RFCIConfig

    config = RFCIConfig()

    assert config.model_dump(mode="json") == {
        "enabled": False,
        "py_tetrad_commit": PINNED_COMMIT,
        "jpype_version": "1.7.1",
        "minimum_java_major": 21,
        "alpha": 0.05,
        "depth": 3,
        "max_discriminating_path_length": 6,
        "timeout_seconds": 180.0,
    }
    with pytest.raises(ValidationError):
        RFCIConfig(unexpected=True)
    with pytest.raises(ValidationError):
        config.enabled = True  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("alpha", 0.0),
        ("alpha", 1.0),
        ("alpha", float("nan")),
        ("depth", -1),
        ("depth", 9),
        ("max_discriminating_path_length", 0),
        ("max_discriminating_path_length", 17),
        ("timeout_seconds", 0.0),
        ("timeout_seconds", 3600.1),
        ("timeout_seconds", float("inf")),
    ),
)
def test_rfci_config_rejects_out_of_bounds_values(field: str, value: object) -> None:
    from secaware.config import RFCIConfig

    with pytest.raises(ValidationError):
        RFCIConfig(**{field: value})


def test_app_config_carries_a_disabled_rfci_gate_by_default() -> None:
    from secaware.config import AppConfig, RFCIConfig

    config = AppConfig.model_validate(
        {
            "run": {"name": "rfci-test"},
            "data": {
                "prompts_path": "prompts.jsonl",
                "prompt_attestations_path": "attestations.jsonl",
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
            "intervention": {"executor": "deterministic"},
        }
    )

    assert type(config.rfci) is RFCIConfig
    assert config.rfci.enabled is False


def test_disabled_detection_does_not_probe_java_import_or_start_jpype(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.config import RFCIConfig
    from secaware.discovery import rfci_backend

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("disabled RFCI must not probe optional runtime")

    original_import = builtins.__import__

    def guarded_import(name: str, *args: object, **kwargs: object) -> object:
        if name.split(".", 1)[0] in {"jpype", "pytetrad"}:
            raise AssertionError("disabled RFCI must not import optional runtime")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(rfci_backend.importlib.util, "find_spec", forbidden)
    monkeypatch.setattr(rfci_backend.importlib.metadata, "version", forbidden)
    monkeypatch.setattr(rfci_backend, "_runtime_python_version", forbidden)
    monkeypatch.setattr(rfci_backend, "_inspect_py_tetrad_installation", forbidden)
    monkeypatch.setattr(rfci_backend, "_detect_java_major", forbidden)

    capability = rfci_backend.detect_rfci_capability(RFCIConfig())

    assert capability.available is False
    assert capability.status == "disabled"
    assert capability.requires_java is True
    assert capability.reason_code == "disabled"
    assert capability.java_major is None
    assert capability.jpype_version is None
    assert capability.python_version == "0.0"


def test_runtime_version_probe_exception_is_safe_unavailability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.config import RFCIConfig
    from secaware.discovery import rfci_backend

    monkeypatch.setattr(
        rfci_backend,
        "_runtime_python_version",
        lambda: (_ for _ in ()).throw(OSError("private runtime detail")),
    )

    capability = rfci_backend.detect_rfci_capability(RFCIConfig(enabled=True))

    assert capability.status == "unavailable"
    assert capability.reason_code == "capability_probe_failed"
    assert capability.python_version == "0.0"


@pytest.mark.parametrize(
    "candidate",
    (None, 312, object(), "3." + "1" * (64 * 1024)),
    ids=("none", "integer", "object", "oversized-string"),
)
def test_malformed_runtime_version_is_safe_and_stops_downstream_probes(
    monkeypatch: pytest.MonkeyPatch,
    candidate: object,
) -> None:
    from secaware.config import RFCIConfig
    from secaware.discovery import rfci_backend

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("malformed runtime version must stop capability probing")

    original_import = builtins.__import__

    def guarded_import(name: str, *args: object, **kwargs: object) -> object:
        if name.split(".", 1)[0] in {"jpype", "pytetrad"}:
            raise AssertionError("malformed runtime version must not import optional runtime")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(rfci_backend, "_runtime_python_version", lambda: candidate)
    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(rfci_backend.importlib.util, "find_spec", forbidden)
    monkeypatch.setattr(rfci_backend.importlib.metadata, "version", forbidden)
    monkeypatch.setattr(rfci_backend, "_inspect_py_tetrad_installation", forbidden)
    monkeypatch.setattr(rfci_backend, "_detect_java_major", forbidden)

    capability = rfci_backend.detect_rfci_capability(RFCIConfig(enabled=True))

    assert capability.status == "unavailable"
    assert capability.reason_code == "capability_probe_failed"
    assert capability.python_version == "0.0"


def test_direct_url_metadata_is_read_with_a_hard_byte_limit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    from pathlib import Path

    from secaware.discovery import rfci_backend

    root = Path(str(tmp_path))
    direct_url = root / "py_tetrad-0.1.dist-info" / "direct_url.json"
    jar = root / "pytetrad" / "resources" / "tetrad-current.jar"
    direct_url.parent.mkdir(parents=True)
    jar.parent.mkdir(parents=True)
    direct_url.write_bytes(b"x" * (rfci_backend._MAX_DIRECT_URL_BYTES + 1))
    jar.write_bytes(b"jar")

    class Distribution:
        files = (
            Path("py_tetrad-0.1.dist-info/direct_url.json"),
            Path("pytetrad/resources/tetrad-current.jar"),
        )

        def locate_file(self, item: object) -> Path:
            return root / Path(str(item))

        def read_text(self, _name: str) -> str:
            raise AssertionError("unbounded Distribution.read_text must not be used")

    monkeypatch.setattr(rfci_backend.importlib.metadata, "distribution", lambda _name: Distribution())

    commit, _jar_sha = rfci_backend._inspect_py_tetrad_installation()

    assert commit is None


@pytest.mark.parametrize("producer", ("overflow", "timeout"))
def test_java_probe_caps_output_and_cleans_up_overflow_or_timeout(
    monkeypatch: pytest.MonkeyPatch,
    producer: str,
) -> None:
    from secaware.discovery import rfci_backend

    class Stream:
        closed = False

        def read(self, size: int) -> bytes:
            if self.closed or producer == "timeout":
                return b""
            return b"x" * size

        def close(self) -> None:
            self.closed = True

    class Process:
        pid = 2_147_483_646

        def __init__(self) -> None:
            self.stdout = Stream()
            self.returncode: int | None = None
            self.killed = False
            self.waited = False

        def poll(self) -> int | None:
            return self.returncode

        def kill(self) -> None:
            self.killed = True
            self.returncode = -9
            self.stdout.close()

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            self.waited = True
            return -9 if self.returncode is None else self.returncode

    process = Process()
    taskkill_calls: list[list[str]] = []

    def taskkill_only(command: list[str], *_args: object, **_kwargs: object) -> object:
        if not command or command[0] != "taskkill":
            raise AssertionError("java probe must not use capture_output subprocess.run")
        taskkill_calls.append(command)
        return object()

    monkeypatch.setattr(rfci_backend.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(rfci_backend.subprocess, "run", taskkill_only)
    monkeypatch.setattr(rfci_backend, "_JAVA_PROBE_TIMEOUT_SECONDS", 0.05)

    assert rfci_backend._detect_java_major() is None
    assert process.killed is True
    assert process.waited is True
    assert process.stdout.closed is True
    if rfci_backend.os.name == "nt":
        assert taskkill_calls
    assert not any(
        thread.name == "secaware-java-version-reader" and thread.is_alive()
        for thread in __import__("threading").enumerate()
    )


def test_no_argument_detection_is_an_active_nonfatal_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.discovery import rfci_backend

    monkeypatch.setattr(rfci_backend, "_runtime_python_version", lambda: "3.12.9")
    monkeypatch.setattr(rfci_backend.importlib.util, "find_spec", lambda _name: None)

    capability = rfci_backend.detect_rfci_capability()

    assert capability.available is False
    assert capability.status == "unavailable"
    assert capability.reason_code == "jpype_missing"


def test_python_310_minimum_backend_skips_all_optional_runtime_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.config import RFCIConfig
    from secaware.discovery import rfci_backend

    monkeypatch.setattr(rfci_backend, "_runtime_python_version", lambda: "3.10.14")
    monkeypatch.setattr(
        rfci_backend.importlib.util,
        "find_spec",
        lambda _name: pytest.fail("Python 3.10 must not probe RFCI dependencies"),
    )
    monkeypatch.setattr(
        rfci_backend,
        "_detect_java_major",
        lambda: pytest.fail("Python 3.10 must not probe Java"),
    )

    capability = rfci_backend.detect_rfci_capability(RFCIConfig(enabled=True))

    assert capability.status == "unavailable"
    assert capability.reason_code == "python_version_unsupported"
    assert capability.python_version == "3.10.14"


@pytest.mark.parametrize(
    ("present", "reason", "jpype_version"),
    (
        (frozenset(), "jpype_missing", None),
        (frozenset({"jpype"}), "py_tetrad_missing", "1.7.1"),
    ),
)
def test_missing_optional_dependencies_are_nonfatal(
    monkeypatch: pytest.MonkeyPatch,
    present: frozenset[str],
    reason: str,
    jpype_version: str | None,
) -> None:
    from secaware.config import RFCIConfig
    from secaware.discovery import rfci_backend

    monkeypatch.setattr(rfci_backend, "_runtime_python_version", lambda: "3.12.9")
    monkeypatch.setattr(
        rfci_backend.importlib.util,
        "find_spec",
        lambda name: object() if name in present else None,
    )
    monkeypatch.setattr(rfci_backend.importlib.metadata, "version", lambda _name: "1.7.1")

    capability = rfci_backend.detect_rfci_capability(RFCIConfig(enabled=True))

    assert capability.available is False
    assert capability.status == "unavailable"
    assert capability.reason_code == reason
    assert capability.jpype_version == jpype_version


def test_jpype_version_drift_is_recorded_without_importing_jpype(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.config import RFCIConfig

    backend = _enable_probe(monkeypatch)
    monkeypatch.setattr(backend.importlib.metadata, "version", lambda _name: "1.6.0")

    capability = backend.detect_rfci_capability(RFCIConfig(enabled=True))

    assert capability.reason_code == "jpype_version_mismatch"
    assert capability.jpype_version == "1.6.0"
    assert capability.java_major is None


@pytest.mark.parametrize(
    ("commit", "jar_sha256", "reason"),
    (
        ("f" * 40, PINNED_JAR_SHA256, "py_tetrad_commit_mismatch"),
        (PINNED_COMMIT, None, "tetrad_jar_missing"),
        (PINNED_COMMIT, "f" * 64, "tetrad_jar_hash_mismatch"),
    ),
)
def test_py_tetrad_commit_and_jar_drift_are_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    commit: str,
    jar_sha256: str | None,
    reason: str,
) -> None:
    from secaware.config import RFCIConfig

    backend = _enable_probe(monkeypatch)
    monkeypatch.setattr(
        backend,
        "_inspect_py_tetrad_installation",
        lambda: (commit, jar_sha256),
    )

    capability = backend.detect_rfci_capability(RFCIConfig(enabled=True))

    assert capability.available is False
    assert capability.reason_code == reason
    assert capability.py_tetrad_commit == commit
    assert capability.tetrad_jar_sha256 == jar_sha256
    assert capability.java_major is None


@pytest.mark.parametrize(
    ("java_major", "reason"),
    ((None, "java_missing"), (17, "java_version_unsupported")),
)
def test_missing_or_old_java_is_optional_unavailability(
    monkeypatch: pytest.MonkeyPatch,
    java_major: int | None,
    reason: str,
) -> None:
    from secaware.config import RFCIConfig

    backend = _enable_probe(monkeypatch)
    monkeypatch.setattr(backend, "_detect_java_major", lambda: java_major)

    capability = backend.detect_rfci_capability(RFCIConfig(enabled=True))

    assert capability.available is False
    assert capability.reason_code == reason
    assert capability.java_major == java_major


def test_python_312_pinned_capability_is_available_and_strict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from secaware.config import RFCIConfig
    from secaware.schema.outcomes import RFCICapabilityRecord

    backend = _enable_probe(monkeypatch)
    capability = backend.detect_rfci_capability(RFCIConfig(enabled=True))

    assert capability.model_dump(mode="json") == {
        "schema_version": "1.0",
        "available": True,
        "status": "available",
        "requires_java": True,
        "python_version": "3.12.9",
        "java_major": 21,
        "jpype_version": "1.7.1",
        "py_tetrad_commit": PINNED_COMMIT,
        "tetrad_jar_sha256": PINNED_JAR_SHA256,
        "reason_code": None,
    }
    with pytest.raises(ValidationError):
        RFCICapabilityRecord.model_validate(
            {**capability.model_dump(mode="json"), "unexpected": True}
        )
    with pytest.raises(ValidationError):
        capability.status = "unavailable"  # type: ignore[misc]
    forged = deepcopy(capability)
    object.__setattr__(forged, "status", "unavailable")
    with pytest.raises(ValidationError):
        RFCICapabilityRecord.model_validate(forged)


def test_probe_exceptions_never_escape_optional_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    from secaware.config import RFCIConfig

    backend = _enable_probe(monkeypatch)
    monkeypatch.setattr(
        backend,
        "_inspect_py_tetrad_installation",
        lambda: (_ for _ in ()).throw(OSError("private host path")),
    )

    capability = backend.detect_rfci_capability(RFCIConfig(enabled=True))

    assert capability.available is False
    assert capability.status == "unavailable"
    assert capability.reason_code == "capability_probe_failed"
    assert "private host path" not in repr(capability)
