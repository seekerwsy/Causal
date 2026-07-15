import ast
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secaware import cli as cli_module
from secaware.cli import app
from secaware.extractors.base import ExtractionPolicy
from secaware.extractors.llm_direct_graph import (
    LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256,
    direct_graph_request_payload,
)
from secaware.extractors.llm_facts import (
    LLM_FACTS_SYSTEM_TEMPLATE_SHA256,
    facts_request_payload,
)
from secaware.intervention.attestation import PromptRoleAttestationRecord, contrast_id
from secaware.intervention.executors import INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE_SHA256
from secaware.io.jsonl import read_jsonl
from secaware.schema.experiments import (
    ConfirmationProtocolInstanceRecord,
    ConfirmationProtocolRecord,
    PromptRole,
    TargetInstanceRecord,
    TargetSpecRecord,
)
from secaware.schema.features import FeatureOperation, PromptExtractorBackend
from secaware.schema.prompt_extraction import MAX_RAW_RESPONSE_CHARS
from secaware.schema.records import PromptRecord
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


PROJECT_ROOT = Path(__file__).resolve().parents[1]
M5_STAGE_PATHS = (
    PROJECT_ROOT / "src" / "secaware" / "pipeline" / "stages" / "prompt_variants.py",
    PROJECT_ROOT / "src" / "secaware" / "pipeline" / "stages" / "randomization.py",
    PROJECT_ROOT / "src" / "secaware" / "pipeline" / "stages" / "confirmation_generation.py",
    PROJECT_ROOT / "src" / "secaware" / "pipeline" / "stages" / "confirmation_oracle.py",
)


def _imported_symbols(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name.casefold() for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").casefold()
            imports.extend(f"{module}.{alias.name.casefold()}" for alias in node.names)
    return tuple(imports)


def _registered_command_names() -> set[str]:
    return {command.name for command in app.registered_commands if command.name is not None}


def _blind_prompt() -> PromptRecord:
    return PromptRecord(
        prompt_id="prompt-blind",
        task_id="task-blind",
        split="confirm",
        language="python",
        task_family="path_handling",
        cwe="CWE-22",
        prompt="Read a caller-supplied path and return the text.",
        prompt_role=PromptRole.NEUTRAL_BASELINE,
    )


def _extraction_policy(backend: PromptExtractorBackend) -> ExtractionPolicy:
    return ExtractionPolicy(
        backend=backend,
        policy_sha256="a" * 64,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        max_response_chars=MAX_RAW_RESPONSE_CHARS,
    )


def test_m5_has_no_code_tsg_or_unsafe_remove_surface() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (PROJECT_ROOT / "src" / "secaware").rglob("*.py")
    )
    assert "Code" + "TSG" not in source
    assert "code_" + "mechanism" not in source
    assert "skip validation" not in source.casefold()
    assert "use an unsafe" not in source.casefold()
    assert "unsafe-" + "remove" not in source.casefold()


def test_randomization_cannot_import_outcomes_or_oracle() -> None:
    imports = _imported_symbols(
        PROJECT_ROOT / "src" / "secaware" / "experiments" / "randomization.py"
    )
    assert all("oracle" not in item and "outcome" not in item for item in imports)


def test_semantic_target_and_protocol_types_have_no_task_prompt_coordinates() -> None:
    forbidden = {"task_id", "source_prompt_id", "counterpart_prompt_id"}
    assert forbidden.isdisjoint(TargetSpecRecord.model_fields)
    assert forbidden.isdisjoint(ConfirmationProtocolRecord.model_fields)
    assert {"task_id", "source_prompt_id"} <= set(TargetInstanceRecord.model_fields)
    assert {"task_id", "source_prompt_id"} <= set(ConfirmationProtocolInstanceRecord.model_fields)


def test_m5_commands_replace_legacy_two_arm_surface() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0, result.output
    for command in (
        "build-confirmation-variants",
        "randomize-confirmation",
        "generate-confirmation",
        "run-oracle",
    ):
        assert command in result.stdout
    for removed in ("intervene", "generate-counterfactual"):
        assert removed not in result.stdout
        assert removed not in _registered_command_names()


def test_run_oracle_confirmation_condition_dispatches_only_to_confirmation_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel_config = object()
    sentinel_store = object()
    calls: list[tuple[object, object, bool]] = []
    monkeypatch.setattr(
        cli_module,
        "_load",
        lambda _config, _run_dir: (sentinel_config, sentinel_store),
    )
    monkeypatch.setattr(
        cli_module,
        "run_confirmation_oracle_stage",
        lambda config, store, *, force: calls.append((config, store, force)),
    )
    monkeypatch.setattr(
        cli_module,
        "run_oracle_stage",
        lambda *_args, **_kwargs: pytest.fail("legacy Oracle dispatch must not run"),
    )

    result = CliRunner().invoke(
        app,
        ["run-oracle", "--config", "unused.yaml", "--condition", "confirmation", "--force"],
    )

    assert result.exit_code == 0, result.output
    assert calls == [(sentinel_config, sentinel_store, True)]


def test_run_oracle_help_exposes_only_observed_and_confirmation_conditions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    help_result = CliRunner().invoke(app, ["run-oracle", "--help"])

    assert help_result.exit_code == 0, help_result.output
    normalized = " ".join(help_result.output.split()).casefold()
    assert "observed" in normalized
    assert "confirmation" in normalized
    assert "counterfactual" not in normalized

    load_calls: list[tuple[object, object]] = []
    monkeypatch.setattr(
        cli_module,
        "_load",
        lambda config, run_dir: load_calls.append((config, run_dir)),
    )
    for invalid in ("counterfactual", "unknown"):
        result = CliRunner().invoke(
            app,
            ["run-oracle", "--config", "unused.yaml", "--condition", invalid],
        )
        assert result.exit_code == 2, result.output
    assert load_calls == []


def test_m5_public_stage_package_exports_the_complete_pipeline() -> None:
    from secaware.pipeline import stages

    for name in (
        "assemble_causal_tables_stage",
        "fci_discovery_stage",
        "run_prompt_variant_freeze_stage",
        "run_confirmation_randomization_stage",
        "run_confirmation_generation_stage",
        "run_confirmation_oracle_stage",
    ):
        assert callable(getattr(stages, name))


def test_executor_and_extractors_have_distinct_system_template_hashes() -> None:
    hashes = {
        INTERVENTION_EXECUTOR_SYSTEM_TEMPLATE_SHA256,
        LLM_FACTS_SYSTEM_TEMPLATE_SHA256,
        LLM_DIRECT_GRAPH_SYSTEM_TEMPLATE_SHA256,
    }
    assert len(hashes) == 3


def test_variant_extractor_requests_are_blind_to_arm_and_target_labels() -> None:
    prompt = _blind_prompt()
    payloads = (
        facts_request_payload(prompt, _extraction_policy(PromptExtractorBackend.LLM_FACTS_V1)),
        direct_graph_request_payload(
            prompt,
            _extraction_policy(PromptExtractorBackend.LLM_DIRECT_GRAPH_V1),
        ),
    )

    for payload in payloads:
        assert "arm" not in payload
        assert "target" not in payload
        assert "prompt_text" in payload


def test_forward_reverse_views_cannot_duplicate_one_attested_contrast() -> None:
    attestations = read_jsonl(
        PROJECT_ROOT / "data" / "examples" / "prompt_attestations_demo.jsonl",
        PromptRoleAttestationRecord,
        required=True,
        allow_empty=False,
    )
    variants = tuple(
        item for item in attestations if item.prompt_role is not PromptRole.NEUTRAL_BASELINE
    )

    forward_reverse = tuple(
        (
            contrast_id(item, FeatureOperation.ADD),
            contrast_id(item, FeatureOperation.REMOVE),
        )
        for item in variants
    )
    assert all(forward == reverse for forward, reverse in forward_reverse)
    owned_contrasts = tuple(contrast_id(item, item.contrast_owner_operation) for item in variants)
    assert len(owned_contrasts) == len(set(owned_contrasts))


def test_post_randomization_m5_stages_do_not_filter_primary_itt_diagnostics() -> None:
    forbidden_diagnostics = {
        "target_changed",
        "semantic_valid",
        "semantic_validity",
        "semantic_compliance",
    }
    for path in M5_STAGE_PATHS[2:]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        names = {node.id.casefold() for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
            node.attr.casefold() for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        assert forbidden_diagnostics.isdisjoint(names)
        assert all("analysis.effects" not in item for item in _imported_symbols(path))


def test_m5_stages_acquire_producer_leases_in_total_order() -> None:
    for path in M5_STAGE_PATHS:
        source = path.read_text(encoding="utf-8")
        assert "producer_outputs =" in source
        assert (
            "hold_dependency_stages(tuple(producer_outputs))" in source
            or "for producer_stage in sorted(producer_outputs)" in source
        )


def test_randomized_confirmation_migration_documents_every_frozen_boundary() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    migration_path = PROJECT_ROOT / "docs" / "migrations" / "randomized-confirmation.md"
    assert migration_path.is_file()
    migration = " ".join(migration_path.read_text(encoding="utf-8").split()).casefold()

    assert "randomized-confirmation.md" in readme
    required_phrases = (
        "source prompt roles",
        "exact positive/neutral counterparts",
        "securityneutralpromptinvariant",
        "per-arm alloweddelta",
        "hard pre-randomization exclusion",
        "diagnostics",
        "text-native",
        "graph-native",
        "llm executor simplifying assumption",
        "separate extractor role",
        "complete blocks",
        "seed slots",
        "assignment commit point",
        "terminal-no-code",
        "intervene",
        "generate-counterfactual",
        "two-arm artifacts",
    )
    for phrase in required_phrases:
        assert phrase in migration
