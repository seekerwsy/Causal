"""Independent schema-3 result verification.

Only frozen record types and serialization helpers are shared with production.
Statistical reconstruction remains local to this package.
"""

from prompt_mechanism_study.verification.design import (
    verify_target_randomization,
    verify_target_study_freezes,
)
from prompt_mechanism_study.verification.effects import verify_target_shared_evidence
from prompt_mechanism_study.verification.integrity import (
    TARGET_RESULT_PACKAGE_FILES,
    target_result_package_index,
)
from prompt_mechanism_study.verification.qualification import (
    verify_formal_budget_preflight,
    verify_rq1_budget_qualification,
    verify_target_power_simulation,
)
from prompt_mechanism_study.verification.reporting import (
    verify_formal_report_authorization,
    verify_target_rq_tables,
)
from prompt_mechanism_study.verification.verifier import (
    load_and_verify_target_result_bundle,
    verify_target_result_components,
)

__all__ = [
    "TARGET_RESULT_PACKAGE_FILES",
    "load_and_verify_target_result_bundle",
    "target_result_package_index",
    "verify_formal_report_authorization",
    "verify_formal_budget_preflight",
    "verify_rq1_budget_qualification",
    "verify_target_power_simulation",
    "verify_target_randomization",
    "verify_target_result_components",
    "verify_target_rq_tables",
    "verify_target_shared_evidence",
    "verify_target_study_freezes",
]
