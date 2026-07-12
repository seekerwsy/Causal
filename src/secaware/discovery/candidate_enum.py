from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from secaware.schema.hypotheses import FactorType
from secaware.schema.tsg import MotifId
from secaware.tsg.catalog import prompt_ontology_entry
from secaware.tsg.motifs import MOTIF_SPECS


@dataclass(frozen=True, slots=True)
class FactorSpec:
    factor_type: FactorType
    motif_id: MotifId
    requirement_label: str
    guard_label: str
    patch_operator: str
    cwe: str
    task_family: str
    label: str


_INTERVENTION_METADATA = MappingProxyType(
    {
        FactorType.INPUT_VALIDATION: (
            "add_input_validation_requirement",
            "generic",
            "Input validation reduces sensitive sink risk",
        ),
        FactorType.PATH_NORMALIZATION: (
            "add_path_normalization_requirement",
            "path_handling",
            "Path normalization reduces path traversal risk",
        ),
        FactorType.SQL_PARAMETERIZATION: (
            "add_sql_parameterization_requirement",
            "sql_query",
            "SQL parameterization reduces injection risk",
        ),
        FactorType.SAFE_SUBPROCESS: (
            "add_safe_subprocess_requirement",
            "command_execution",
            "Safe subprocess invocation reduces command injection risk",
        ),
        FactorType.AUTHORIZATION_CHECK: (
            "add_authorization_check_requirement",
            "authorization",
            "Authorization checks reduce missing authorization risk",
        ),
        FactorType.SAFE_DESERIALIZATION: (
            "add_safe_deserialization_requirement",
            "deserialization",
            "Safe deserialization reduces unsafe object loading risk",
        ),
    }
)


def _build_factor_specs() -> Mapping[FactorType, FactorSpec]:
    motif_by_factor = {spec.factor_type: spec for spec in MOTIF_SPECS.values()}
    specs: dict[FactorType, FactorSpec] = {}
    for factor_type in FactorType:
        catalog = prompt_ontology_entry(factor_type)
        motif = motif_by_factor[factor_type]
        patch_operator, task_family, label = _INTERVENTION_METADATA[factor_type]
        specs[factor_type] = FactorSpec(
            factor_type=factor_type,
            motif_id=motif.motif_id,
            requirement_label=catalog.requirement_label,
            guard_label=catalog.guard_label,
            patch_operator=patch_operator,
            cwe=catalog.cwe,
            task_family=task_family,
            label=label,
        )
    if (
        tuple(specs) != tuple(FactorType)
        or len(specs) != 6
        or set(motif_by_factor) != set(FactorType)
        or {spec.motif_id for spec in specs.values()} != set(MotifId)
    ):
        raise RuntimeError("invalid discovery factor catalog")
    return MappingProxyType(specs)


FACTOR_SPECS: Mapping[FactorType, FactorSpec] = _build_factor_specs()


__all__ = ["FACTOR_SPECS", "FactorSpec"]
