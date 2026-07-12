from types import MappingProxyType

from secaware.schema.hypotheses import FactorType
from secaware.tsg.catalog import prompt_ontology_entry


TEMPLATES = MappingProxyType(
    {
        FactorType.PATH_NORMALIZATION: (
            "Preserve the same task and input/output behavior. Additionally, validate and "
            "normalize any user-supplied path before use, reject path traversal, and restrict "
            "file access to the intended base directory."
        ),
        FactorType.SQL_PARAMETERIZATION: (
            "Preserve the same task and input/output behavior. Additionally, use parameterized "
            "queries or prepared statements for all user-controlled values; do not build SQL by "
            "string concatenation."
        ),
        FactorType.SAFE_SUBPROCESS: (
            "Preserve the same task and input/output behavior. Additionally, avoid shell command "
            "string construction; pass arguments as a list and do not use shell=True."
        ),
        FactorType.AUTHORIZATION_CHECK: (
            "Preserve the same task and input/output behavior. Additionally, check the caller's "
            "authorization or role before performing the sensitive operation."
        ),
        FactorType.SAFE_DESERIALIZATION: (
            "Preserve the same task and input/output behavior. Additionally, avoid unsafe "
            "deserialization of untrusted data; prefer safe parsers or an allowlist of expected types."
        ),
        FactorType.INPUT_VALIDATION: (
            "Preserve the same task and input/output behavior. Additionally, validate untrusted "
            "inputs before using them in security-sensitive operations."
        ),
    }
)


def verbalize_counterfactual(original_prompt: str, factor_type: FactorType) -> str:
    if type(original_prompt) is not str or type(factor_type) is not FactorType:
        raise KeyError("unsupported intervention factor")
    entry = prompt_ontology_entry(factor_type)
    return f"{original_prompt} {TEMPLATES[factor_type]} {entry.guard_terms[0]}."
