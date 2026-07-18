from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import get_args

import tomllib

from typer.testing import CliRunner

from secaware.causal.variable_catalog import PROMPT_CAUSAL_VARIABLES
from secaware.cli import app
from secaware.config import RFCIConfig
from secaware.io.run_store import RunStore
from secaware.pipeline.stages.causal_tables import CAUSAL_TABLE_OUTPUTS
from secaware.pipeline.stages.confirmation_generation import CONFIRMATION_GENERATION_OUTPUTS
from secaware.pipeline.stages.effects import EFFECT_STAGE_OUTPUTS
from secaware.pipeline.stages.fci_discovery import FCI_DISCOVERY_OUTPUTS
from secaware.pipeline.stages.jci import JCI_STAGE_OUTPUTS
from secaware.pipeline.stages.prompt_variants import PROMPT_VARIANT_OUTPUTS
from secaware.pipeline.stages.randomization import RANDOMIZATION_OUTPUTS
from secaware.pipeline.stages.reporting import REPORT_STAGE_OUTPUTS
from secaware.pipeline.stages.rfci import RFCI_STAGE_OUTPUTS
from secaware.schema.causal import (
    CausalTableRecord,
    CausalVariableSpec,
    JCIBackgroundKnowledgeRecord,
    JCIContextSpec,
    JCIStratum,
    PAGRunKind,
)
from secaware.schema.outcomes import JCIOrientationDeltaRecord


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "secaware"

_LEGACY_MODULES = (
    "analysis/bootstrap.py",
    "analysis/effects.py",
    "analysis/pairing.py",
    "schema/results.py",
    "schema/interventions.py",
    "schema/hypotheses.py",
    "discovery/candidate_enum.py",
    "discovery/scoring.py",
    "discovery/tsg_qcd.py",
    "intervention/operators.py",
    "intervention/validator.py",
    "intervention/verbalizer.py",
    "pipeline/legacy_discovery.py",
)
_LEGACY_IMPORTS = {
    "secaware." + value.removesuffix(".py").replace("/", ".") for value in _LEGACY_MODULES
}
_LEGACY_TESTS = (
    "test_discovery.py",
    "test_discovery_graph_scoring.py",
    "test_intervention.py",
    "test_intervention_graph_validation.py",
    "test_generation_planner.py",
    "test_generation_cli.py",
    "test_provider_generation_cli.py",
    "test_oracle_cli.py",
)
_FINAL_COMMANDS = {
    "preflight",
    "extract-prompt-tsg",
    "generate-observed",
    "run-oracle",
    "discover",
    "build-confirmation-variants",
    "randomize-confirmation",
    "generate-confirmation",
    "import-functional-outcomes",
    "confirm",
    "analyze-jci",
    "analyze-rfci",
    "report",
    "run-all",
}
_BATCH_B_RETIRED_IMPORTS = {
    "secaware.schema.hypotheses",
    "secaware.schema.interventions",
    "secaware.schema.results",
    "secaware.analysis.effects",
    "secaware.analysis.pairing",
    "secaware.discovery.tsg_qcd",
    "secaware.intervention.operators",
}
_PYTHON312_SELF_MODULES = (
    "schema/causal.py",
    "schema/experiments.py",
    "schema/outcomes.py",
    "intervention/attestation.py",
    "intervention/graph_patch.py",
    "intervention/executors.py",
)
_TOMLLIB_TEST_MODULES = (
    "test_m6_architecture.py",
    "test_m4b_architecture.py",
    "test_packaging.py",
)


def _python_sources() -> tuple[Path, ...]:
    return tuple(sorted(SOURCE_ROOT.rglob("*.py")))


def _imported_modules(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.append(node.module)
            imported.extend(f"{node.module}.{alias.name}" for alias in node.names)
    return tuple(imported)


def _split_comparisons(path: Path) -> set[tuple[type[ast.cmpop], str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    comparisons: set[tuple[type[ast.cmpop], str]] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Attribute)
            and node.left.attr == "split"
            and len(node.ops) == 1
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Constant)
            and isinstance(node.comparators[0].value, str)
        ):
            comparisons.add((type(node.ops[0]), node.comparators[0].value))
    return comparisons


def _declared_command_names() -> set[str]:
    return {command.name for command in app.registered_commands if command.name is not None}


def test_final_tree_has_no_code_tsg_or_code_mechanism_artifact() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in _python_sources())
    forbidden = ("CodeTSG", "CodeMechanismTrace", "code_mechanism", "mechanism_cards")

    assert not any(token in source for token in forbidden)


def test_primary_itt_has_no_diagnostic_filter() -> None:
    tree = ast.parse((SOURCE_ROOT / "analysis" / "itt.py").read_text(encoding="utf-8"))
    identifiers = {node.id.casefold() for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr.casefold() for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }

    assert {
        "target_changed",
        "semantic_valid",
        "semantic_validity",
        "semantic_compliance",
    }.isdisjoint(identifiers)


def test_minimum_import_does_not_start_java() -> None:
    completed = subprocess.run(
        [sys.executable, "-c", "import secaware; import secaware.cli; print('ok')"],
        check=False,
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        env={**os.environ, "JAVA_HOME": ""},
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "ok"


def test_python_runtime_is_fixed_to_the_312_minor_line() -> None:
    metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["requires-python"] == ">=3.12,<3.13"
    assert "typing-extensions" not in "\n".join(metadata["project"]["dependencies"]).casefold()
    assert "tomli" not in "\n".join(metadata["project"]["optional-dependencies"]["dev"]).casefold()

    for relative in _PYTHON312_SELF_MODULES:
        path = SOURCE_ROOT / relative
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        assert any(
            isinstance(node, ast.ImportFrom)
            and node.module == "typing"
            and any(alias.name == "Self" for alias in node.names)
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.ImportFrom) and node.module == "typing_extensions"
            for node in ast.walk(tree)
        )

    for name in _TOMLLIB_TEST_MODULES:
        source = (PROJECT_ROOT / "tests" / name).read_text(encoding="utf-8")
        assert "import tomllib" in source
        tree = ast.parse(source, filename=name)
        assert not any(
            (isinstance(node, ast.Import) and any(alias.name == "tomli" for alias in node.names))
            or (isinstance(node, ast.ImportFrom) and node.module == "tomli")
            for node in ast.walk(tree)
        )


def test_final_cli_registers_analysis_commands() -> None:
    result = CliRunner().invoke(app, ["--help"])
    expected = {
        "import-functional-outcomes",
        "confirm",
        "analyze-jci",
        "analyze-rfci",
        "report",
    }

    assert result.exit_code == 0, result.output
    assert expected <= _declared_command_names()
    assert all(command in result.stdout for command in expected)


def test_final_cli_surface_is_exact_and_legacy_generation_commands_are_retired() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0, result.output
    assert _declared_command_names() == _FINAL_COMMANDS
    assert {
        "plan-generation",
        "generate",
        "import-generation",
        "intervene",
        "generate-counterfactual",
    }.isdisjoint(_declared_command_names())


def test_cli_pipeline_and_generation_have_no_retired_direct_imports() -> None:
    migration_sources = (
        SOURCE_ROOT / "cli.py",
        SOURCE_ROOT / "analysis" / "__init__.py",
        SOURCE_ROOT / "schema" / "__init__.py",
        SOURCE_ROOT / "intervention" / "__init__.py",
        *(SOURCE_ROOT / "pipeline").rglob("*.py"),
        *(SOURCE_ROOT / "generation").rglob("*.py"),
    )
    violations = {
        path.relative_to(PROJECT_ROOT).as_posix(): tuple(
            imported for imported in _imported_modules(path) if imported in _BATCH_B_RETIRED_IMPORTS
        )
        for path in migration_sources
    }

    assert {path: imports for path, imports in violations.items() if imports} == {}


def test_importing_final_cli_does_not_load_batch_b_retired_modules() -> None:
    runtime_forbidden = _BATCH_B_RETIRED_IMPORTS - {"secaware.schema.hypotheses"}
    script = (
        "import sys; import secaware; import secaware.cli; "
        f"forbidden={runtime_forbidden!r}; "
        "print(','.join(sorted(forbidden.intersection(sys.modules))))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == ""


def test_generation_planner_exposes_only_observed_and_randomized_confirmation_paths() -> None:
    planner_path = SOURCE_ROOT / "generation" / "request_planner.py"
    tree = ast.parse(planner_path.read_text(encoding="utf-8"), filename=str(planner_path))
    functions = {
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert "plan_observed_requests" in functions
    assert "plan_confirmation_requests" in functions
    assert "plan_counterfactual_requests" not in functions
    assert "secaware.schema.interventions" not in _imported_modules(planner_path)


def test_cli_has_no_retired_two_arm_or_generic_generation_helpers() -> None:
    cli_tree = ast.parse((SOURCE_ROOT / "cli.py").read_text(encoding="utf-8"))
    functions = {
        node.name
        for node in cli_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert {
        "intervene_stage",
        "generate_counterfactual_stage",
        "confirm_stage",
        "_retired_confirm_stage",
        "plan_generation_stage",
        "import_generation_stage",
        "generate_provider_stage",
    }.isdisjoint(functions)


def test_discovery_and_confirmation_keep_their_held_out_splits() -> None:
    discovery_guards = _split_comparisons(SOURCE_ROOT / "pipeline" / "stages" / "causal_tables.py")
    confirmation_guards = _split_comparisons(
        SOURCE_ROOT / "pipeline" / "stages" / "prompt_variants.py"
    )

    assert discovery_guards
    assert {value for _operator, value in discovery_guards} == {"discover"}
    assert confirmation_guards
    assert {value for _operator, value in confirmation_guards} == {"confirm"}


def test_model_is_a_stratum_coordinate_and_never_a_causal_column() -> None:
    assert "model_id" in CausalTableRecord.model_fields
    assert "model_id" not in CausalVariableSpec.model_fields
    assert tuple(JCIStratum.model_fields) == (
        "scope_id",
        "model_id",
        "hypothesis_id",
        "target_spec_id",
        "arm_protocol_id",
    )
    assert all(item.variable_id != "model_id" for item in PROMPT_CAUSAL_VARIABLES)


def test_jci_uses_one_categorical_context_and_separate_raw_and_constrained_pags() -> None:
    assert get_args(JCIContextSpec.model_fields["variable_id"].annotation) == ("c.arm",)
    assert set(JCIContextSpec.model_fields) == {"variable_id", "arm_roles", "category_codes"}
    assert PAGRunKind.JCI_RAW is not PAGRunKind.JCI_CONSTRAINED
    output_names = {path.as_posix() for path, _model in JCI_STAGE_OUTPUTS}
    assert {
        "analysis/jci_raw_pags.jsonl",
        "analysis/jci_background_knowledge.jsonl",
        "analysis/jci_constrained_pags.jsonl",
        "analysis/jci_orientation_deltas.jsonl",
    } <= output_names


def test_jci_assumption_provenance_cannot_claim_per_assumption_attribution() -> None:
    assert {
        "base_background_knowledge_sha256",
        "assumption_ids",
        "added_forbidden_directions",
        "knowledge_sha256",
    } <= set(JCIBackgroundKnowledgeRecord.model_fields)
    assert {
        "raw_pag_id",
        "constrained_pag_id",
        "assumption_ids",
        "assumption_set_sha256",
        "per_assumption_attribution",
    } <= set(JCIOrientationDeltaRecord.model_fields)
    assert JCIOrientationDeltaRecord.model_fields["per_assumption_attribution"].default is False


def test_rfci_is_an_optional_java_extra_and_never_a_base_dependency() -> None:
    metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    base = "\n".join(metadata["project"]["dependencies"]).casefold()
    rfci_extra = "\n".join(metadata["project"]["optional-dependencies"]["rfci"]).casefold()

    assert RFCIConfig().enabled is False
    assert "jpype" not in base and "py-tetrad" not in base and "java" not in base
    assert "jpype" in rfci_extra and "py-tetrad" in rfci_extra
    assert {path.as_posix() for path, _model in RFCI_STAGE_OUTPUTS} == {
        "analysis/rfci_capability.jsonl",
        "analysis/rfci_pags.jsonl",
        "analysis/rfci_failures.jsonl",
    }


def test_final_analysis_stages_have_complete_sealed_output_contracts() -> None:
    expected = {
        "estimate-confirmation-effects": {
            "analysis/assignment_outcomes.jsonl",
            "analysis/contrast_specs.jsonl",
            "analysis/effect_bootstrap_draws.jsonl",
            "analysis/itt_effects.jsonl",
            "analysis/effect_failures.jsonl",
        },
        "jci-confirmation": {
            "analysis/jci_tables.jsonl",
            "analysis/jci_observations.jsonl",
            "analysis/jci_raw_pags.jsonl",
            "analysis/jci_background_knowledge.jsonl",
            "analysis/jci_constrained_pags.jsonl",
            "analysis/jci_orientation_deltas.jsonl",
            "analysis/jci_failures.jsonl",
        },
        "rfci-confirmation": {
            "analysis/rfci_capability.jsonl",
            "analysis/rfci_pags.jsonl",
            "analysis/rfci_failures.jsonl",
        },
        "report": {path.as_posix() for path in REPORT_STAGE_OUTPUTS},
    }
    actual = {
        "estimate-confirmation-effects": {path.as_posix() for path, _model in EFFECT_STAGE_OUTPUTS},
        "jci-confirmation": {path.as_posix() for path, _model in JCI_STAGE_OUTPUTS},
        "rfci-confirmation": {path.as_posix() for path, _model in RFCI_STAGE_OUTPUTS},
        "report": {path.as_posix() for path in REPORT_STAGE_OUTPUTS},
    }

    assert actual == expected
    assert all(
        RunStore._requires_output_seal(stage) for stage in ("import-functional-outcomes", *expected)
    )


def test_executor_and_intervention_mode_are_provenance_not_causal_variables() -> None:
    forbidden = ("executor", "intervention_mode", "generation_mode")
    columns = tuple(item.variable_id.casefold() for item in PROMPT_CAUSAL_VARIABLES)
    queries = tuple(item.query_id.casefold() for item in PROMPT_CAUSAL_VARIABLES)

    assert all(not any(token in value for token in forbidden) for value in (*columns, *queries))
    assert not ({"executor", "mode", "intervention_mode"} & set(CausalVariableSpec.model_fields))


def test_final_tree_has_no_benchmark_or_ranking_implementation_surface() -> None:
    forbidden = ("benchmark", "ranking", "rank_backends", "select_best", "winner_selection")
    violations: list[str] = []
    for path in _python_sources():
        if any(token in path.stem.casefold() for token in forbidden):
            violations.append(path.relative_to(PROJECT_ROOT).as_posix())
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and any(
                token in node.name.casefold() for token in forbidden
            ):
                violations.append(f"{path.relative_to(PROJECT_ROOT)}:{node.name}")

    assert violations == []


def test_legacy_modules_and_tests_are_removed_after_zero_live_import_migration() -> None:
    assert all(not (SOURCE_ROOT / relative).exists() for relative in _LEGACY_MODULES)
    assert all(not (PROJECT_ROOT / "tests" / name).exists() for name in _LEGACY_TESTS)

    violations = {
        path.relative_to(PROJECT_ROOT).as_posix(): tuple(
            imported
            for imported in _imported_modules(path)
            if any(
                imported == legacy or imported.startswith(f"{legacy}.")
                for legacy in _LEGACY_IMPORTS
            )
        )
        for path in _python_sources()
    }
    assert {path: imports for path, imports in violations.items() if imports} == {}


def test_report_layer_has_no_lazy_cycle_back_into_pipeline() -> None:
    tables_path = SOURCE_ROOT / "reports" / "tables.py"
    tables_tree = ast.parse(tables_path.read_text(encoding="utf-8"), filename=str(tables_path))
    report_functions = {
        node.name
        for node in ast.walk(tables_tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert "write_reports" not in report_functions
    report_sources = tuple((SOURCE_ROOT / "reports").glob("*.py"))
    assert {
        path.name: imported
        for path in report_sources
        for imported in _imported_modules(path)
        if imported.startswith("secaware.pipeline")
    } == {}
    assert "write_reports" not in (SOURCE_ROOT / "reports" / "__init__.py").read_text(
        encoding="utf-8"
    )


def test_prompt_only_fci_jci_migration_documents_regeneration_and_every_artifact() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    migration_path = PROJECT_ROOT / "docs" / "migrations" / "prompt-only-fci-jci.md"
    assert migration_path.is_file()
    migration = migration_path.read_text(encoding="utf-8")
    readme_prose = " ".join(readme.split())

    assert "[Prompt-only FCI/JCI migration](docs/migrations/prompt-only-fci-jci.md)" in readme
    assert "Randomized ITT is the primary confirmatory estimate." in readme_prose
    assert (
        "JCI is secondary and cannot alter the randomized ITT or frozen hypotheses." in readme_prose
    )

    required_claims = (
        "Prompt TSG edges encode semantic extraction and validation relationships; they are not causal edges and are never supplied to FCI, JCI, or RFCI as causal adjacencies.",
        "PAG circle endpoints remain circles: no report, path query, JCI constraint, or RFCI sensitivity run may silently orient them.",
        "Randomized ITT is the primary confirmatory estimate.",
        "JCI is secondary and cannot alter, replace, filter, or select the randomized ITT or the frozen hypotheses.",
        "RFCI is optional, requires the pinned Java/JPype/py-tetrad runtime, and cannot block or redefine the primary ITT result when unavailable.",
        "Generated code is consumed only by the independent Oracle and an explicitly configured functional evaluator; it is never a causal variable.",
        "Missing, invalid, or unavailable functional evaluation is `unknown`/`non-evaluable`, never a negative outcome.",
        "Best/worst-case bounds retain every randomized assignment and cannot be replaced by complete-case filtering.",
        "Pre-randomization exclusions occur before assignment and are recorded separately; post-assignment failures remain in the assigned ITT arm.",
        "To regenerate, start a new run directory and rerun `secaware run-all`; never delete, edit, or overwrite a sealed artifact or its `.stages/<stage>.json` manifest in a completed run.",
        "Every committed output below is authenticated by its stage manifest's `output_sha256`; record-level IDs and `*_sha256` fields bind semantic content and upstream provenance.",
        "JCI orientation deltas are attributed only to the complete declared assumption set; they cannot be attributed to any individual assumption.",
    )
    assert all(claim in migration for claim in required_claims)
    assert "per-assumption orientation delta" not in migration.casefold()

    artifact_names = {
        "tsg/prompt_extraction_proposals.jsonl",
        "tsg/prompt_tsg.jsonl",
        "generation/observed_requests.jsonl",
        "generation/observed_code.jsonl",
        "generation/observed_attempts.jsonl",
        "oracle/observed_oracle.jsonl",
        *(f"discovery/{name}" for name, _model in CAUSAL_TABLE_OUTPUTS),
        *(f"discovery/{name}" for name, _model in FCI_DISCOVERY_OUTPUTS),
        *(f"interventions/{name}" for name, _model in PROMPT_VARIANT_OUTPUTS),
        *(f"interventions/{name}" for name, _model in RANDOMIZATION_OUTPUTS),
        *(f"generation/{name}" for name, _model in CONFIRMATION_GENERATION_OUTPUTS),
        "oracle/confirmation_oracle.jsonl",
        "analysis/functional_outcomes.jsonl",
        *(path.as_posix() for path, _model in EFFECT_STAGE_OUTPUTS),
        *(path.as_posix() for path, _model in JCI_STAGE_OUTPUTS),
        *(path.as_posix() for path, _model in RFCI_STAGE_OUTPUTS),
        *(path.as_posix() for path in REPORT_STAGE_OUTPUTS),
    }
    inventory_match = re.search(
        r"<!-- artifact-inventory:start -->\n(?P<body>.*?)\n<!-- artifact-inventory:end -->",
        migration,
        flags=re.DOTALL,
    )
    assert inventory_match is not None
    documented_artifacts = set(
        re.findall(r"^- `([^`]+)`$", inventory_match.group("body"), flags=re.MULTILINE)
    )
    assert documented_artifacts == artifact_names
