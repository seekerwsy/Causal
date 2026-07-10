from dataclasses import dataclass

from secaware.schema.hypotheses import FactorType


@dataclass(frozen=True)
class FactorSpec:
    factor_type: FactorType
    prompt_factor: str
    prompt_motif: str
    code_motif: str
    patch_operator: str
    cwe: str
    task_family: str
    label: str


FACTOR_SPECS: dict[FactorType, FactorSpec] = {
    FactorType.PATH_NORMALIZATION: FactorSpec(
        factor_type=FactorType.PATH_NORMALIZATION,
        prompt_factor="factor.path_normalization_required",
        prompt_motif="user_path_to_file_open_without_guard",
        code_motif="code.user_path_to_file_open_without_guard",
        patch_operator="add_path_normalization_requirement",
        cwe="CWE-22",
        task_family="path_handling",
        label="Path normalization reduces path traversal risk",
    ),
    FactorType.SQL_PARAMETERIZATION: FactorSpec(
        factor_type=FactorType.SQL_PARAMETERIZATION,
        prompt_factor="factor.sql_parameterization_required",
        prompt_motif="user_string_to_sql_without_parameterization",
        code_motif="code.user_string_to_sql_without_parameterization",
        patch_operator="add_sql_parameterization_requirement",
        cwe="CWE-89",
        task_family="sql_query",
        label="SQL parameterization reduces injection risk",
    ),
    FactorType.SAFE_SUBPROCESS: FactorSpec(
        factor_type=FactorType.SAFE_SUBPROCESS,
        prompt_factor="factor.safe_subprocess_required",
        prompt_motif="user_input_to_shell_without_guard",
        code_motif="code.user_input_to_shell_without_guard",
        patch_operator="add_safe_subprocess_requirement",
        cwe="CWE-78",
        task_family="command_execution",
        label="Safe subprocess invocation reduces command injection risk",
    ),
    FactorType.AUTHORIZATION_CHECK: FactorSpec(
        factor_type=FactorType.AUTHORIZATION_CHECK,
        prompt_factor="factor.authorization_check_required",
        prompt_motif="sensitive_operation_without_auth_guard",
        code_motif="code.sensitive_operation_without_auth_guard",
        patch_operator="add_authorization_check_requirement",
        cwe="CWE-862",
        task_family="authorization",
        label="Authorization checks reduce missing authorization risk",
    ),
    FactorType.SAFE_DESERIALIZATION: FactorSpec(
        factor_type=FactorType.SAFE_DESERIALIZATION,
        prompt_factor="factor.safe_deserialization_required",
        prompt_motif="untrusted_data_to_deserialization_sink",
        code_motif="code.untrusted_data_to_deserialization_sink",
        patch_operator="add_safe_deserialization_requirement",
        cwe="CWE-502",
        task_family="deserialization",
        label="Safe deserialization reduces unsafe object loading risk",
    ),
    FactorType.INPUT_VALIDATION: FactorSpec(
        factor_type=FactorType.INPUT_VALIDATION,
        prompt_factor="factor.input_validation_required",
        prompt_motif="untrusted_source_to_sensitive_sink_without_guard",
        code_motif="code.untrusted_source_to_sensitive_sink_without_guard",
        patch_operator="add_input_validation_requirement",
        cwe="generic",
        task_family="generic",
        label="Input validation reduces sensitive sink risk",
    ),
}
