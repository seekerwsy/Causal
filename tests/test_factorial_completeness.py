from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.factorial_experiment import (
    FactorialExperimentError,
    _v11_pair_selection,
    _validate_v11_intervention_design,
    _validate_v11_pair_relations,
)
from prompt_mechanism_study.factorial_verify import _verify_pair_selection_provenance
from prompt_mechanism_study.inference import (
    FactorialPattern,
    classify_factorial_pattern,
)
from prompt_mechanism_study.interaction_selector_experiment import (
    INTERACTION_SELECTION_ARTIFACT_FILES,
    freeze_interaction_selection_from_config,
)
from prompt_mechanism_study.intervention import FactorialCell
from prompt_mechanism_study.mechanisms import PairRelation, load_pair_registry
from prompt_mechanism_study.prompt_tsg import load_catalog
from prompt_mechanism_study.records import canonical_json, canonical_value
from test_interaction_selector_experiment import (
    CATALOG_PATH,
    REGISTRY_PATH,
    _catalog_bound_selector_config,
)


@pytest.mark.reviewer
@pytest.mark.parametrize(
    ("cells", "expected"),
    [
        ((0.0, 0.2, 0.3, 0.5), FactorialPattern.ADDITIVE),
        ((0.0, 0.1, 0.1, 0.8), FactorialPattern.POSITIVE_INTERACTION),
        ((0.0, 0.8, 0.8, 0.9), FactorialPattern.NEGATIVE_INTERACTION),
        ((0.0, 1.0, 1.0, 0.0), FactorialPattern.XOR),
        ((0.0, 1.0, 1.0, 1.0), FactorialPattern.REDUNDANT),
        ((0.0, 0.0, 0.0, 1.0), FactorialPattern.PREREQUISITE),
        ((0.0, 1.0, 0.8, 0.2), FactorialPattern.REVERSAL),
    ],
)
def test_factorial_response_surface_classification(cells, expected) -> None:
    assert classify_factorial_pattern(
        dict(zip(FactorialCell, cells, strict=True))
    ) is expected


@pytest.mark.reviewer
def test_noncommutative_pair_requires_both_positive_weight_orders() -> None:
    incomplete = {
        "joint_application_commutative": False,
        "joint_realizations": [
            {"label": "only-forward", "weight": 1, "application_order": [1, 2]}
        ],
    }
    with pytest.raises(FactorialExperimentError, match="require both application orders"):
        _validate_v11_intervention_design(incomplete)

    _validate_v11_intervention_design(
        {
            "joint_application_commutative": True,
            "joint_realizations": incomplete["joint_realizations"],
        }
    )


@pytest.mark.reviewer
def test_factorial_pair_selection_is_derived_from_verified_artifact(
    tmp_path: Path,
) -> None:
    selector_config, pair = _catalog_bound_selector_config(tmp_path)
    registry = load_pair_registry(REGISTRY_PATH, load_catalog(CATALOG_PATH))
    selector_config_path = tmp_path / "interaction-selector.json"
    selector_config_path.write_text(
        canonical_json(selector_config), encoding="utf-8"
    )
    selector_root = tmp_path / "selection"
    selector_report = freeze_interaction_selection_from_config(
        selector_config_path, selector_root
    )
    config = {"pair_selection": {"artifact_path": "selection"}}
    frozen = _v11_pair_selection(
        config,
        registry,
        (pair,),
        repository_root=tmp_path,
        config_root=tmp_path,
    )

    assert frozen.selection_id == selector_report["freeze_id"]
    assert frozen.selected_pair_ids == (pair.pair_id,)
    assert frozen.artifact_bundle_sha256 == selector_report["bundle_sha256"]

    with pytest.raises(
        FactorialExperimentError,
        match="verified interaction selection drifts from factorial pair protocols",
    ):
        _v11_pair_selection(
            config,
            registry,
            (SimpleNamespace(pair_id="pair-b"),),
            repository_root=tmp_path,
            config_root=tmp_path,
        )


@pytest.mark.reviewer
def test_factorial_pair_selection_rejects_self_reported_coordinates(
    tmp_path: Path,
) -> None:
    config = {
        "pair_selection": {
            "selection_id": "selection-from-observational-selector",
            "artifact_bundle_sha256": "a" * 64,
            "selected_pair_ids": ["pair-a"],
        }
    }
    with pytest.raises(FactorialExperimentError, match="provenance is invalid"):
        _v11_pair_selection(
            config,
            SimpleNamespace(name="registry"),
            (SimpleNamespace(pair_id="pair-b"),),
            repository_root=tmp_path,
            config_root=tmp_path,
        )

    with pytest.raises(FactorialExperimentError, match="escapes"):
        _v11_pair_selection(
            {"pair_selection": {"artifact_path": str(tmp_path.parent / "outside")}},
            SimpleNamespace(name="registry"),
            (SimpleNamespace(pair_id="pair-b"),),
            repository_root=tmp_path,
            config_root=tmp_path,
        )


@pytest.mark.reviewer
def test_factorial_v11_rejects_historical_only_pair_relations() -> None:
    registry = load_pair_registry(REGISTRY_PATH, load_catalog(CATALOG_PATH))
    pair = registry.pairs[0]
    _validate_v11_pair_relations((pair,))

    with pytest.raises(FactorialExperimentError, match="active successor vocabulary"):
        _validate_v11_pair_relations(
            (
                replace(
                    pair,
                    relation_type=PairRelation.SEQUENTIAL_CONTROLS,
                ),
            )
        )


@pytest.mark.reviewer
def test_factorial_verifier_replays_portable_selector_and_registry_provenance(
    tmp_path: Path,
) -> None:
    selector_config, pair = _catalog_bound_selector_config(tmp_path)
    selector_config_path = tmp_path / "selector-config.json"
    selector_config_path.write_text(canonical_json(selector_config), encoding="utf-8")
    selector_root = tmp_path / "selector"
    freeze_interaction_selection_from_config(selector_config_path, selector_root)
    registry = load_pair_registry(REGISTRY_PATH, load_catalog(CATALOG_PATH))
    selector_selection = _v11_pair_selection(
        {"pair_selection": {"artifact_path": "selector"}},
        registry,
        (pair,),
        repository_root=tmp_path,
        config_root=tmp_path,
    )
    artifacts = {
        "factorial-pair-registry.json": read_json(REGISTRY_PATH),
        "factorial-prompt-tsg-catalog.json": read_json(CATALOG_PATH),
        **{
            f"pair-selection-{name}": read_json(selector_root / name)
            for name in INTERACTION_SELECTION_ARTIFACT_FILES
        },
    }
    result_root = tmp_path / "selector-result"
    write_bundle(result_root, artifacts)
    selector_study = {
        "prompt_tsg_catalog_sha256": registry.prompt_tsg_catalog_sha256,
        "policies": [{"pair": canonical_value(pair)}],
        "pair_selection": canonical_value(selector_selection),
        "randomization": {"selection_id": selector_selection.selection_id},
    }
    _verify_pair_selection_provenance(
        result_root,
        selector_study,
        {"pair_selection": {"artifact_path": "external-path-is-not-trusted"}},
    )

    tampered = dict(artifacts)
    tampered_report = dict(
        tampered["pair-selection-report.json"]
    )
    tampered_report["selected_pair_ids"] = []
    tampered["pair-selection-report.json"] = tampered_report
    tampered_root = tmp_path / "tampered-selector-result"
    write_bundle(tampered_root, tampered)
    with pytest.raises(ValueError, match="report does not recompute"):
        _verify_pair_selection_provenance(
            tampered_root,
            selector_study,
            {"pair_selection": {"artifact_path": "ignored"}},
        )

    registry_selection = _v11_pair_selection(
        {},
        registry,
        registry.pairs,
        repository_root=tmp_path,
        config_root=tmp_path,
    )
    registry_root = tmp_path / "registry-result"
    write_bundle(
        registry_root,
        {
            "factorial-pair-registry.json": read_json(REGISTRY_PATH),
            "factorial-prompt-tsg-catalog.json": read_json(CATALOG_PATH),
        },
    )
    registry_study = {
        "prompt_tsg_catalog_sha256": registry.prompt_tsg_catalog_sha256,
        "policies": [{"pair": canonical_value(pair)}],
        "pair_selection": canonical_value(registry_selection),
        "randomization": {"selection_id": registry_selection.selection_id},
    }
    _verify_pair_selection_provenance(registry_root, registry_study, {})
    registry_study["pair_selection"] = {
        **registry_study["pair_selection"],
        "selection_id": "synchronized-but-not-derived",
    }
    registry_study["randomization"]["selection_id"] = "synchronized-but-not-derived"
    with pytest.raises(ValueError, match="registry selection drift"):
        _verify_pair_selection_provenance(registry_root, registry_study, {})
