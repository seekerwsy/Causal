"""Exact assignment outcome assembly and independent functional contracts."""

from secaware.outcomes.assembler import assemble_assignment_outcomes
from secaware.outcomes.assembler_v2 import assemble_assignment_outcome_v2
from secaware.outcomes.functional import validate_functional_outcomes

__all__ = [
    "assemble_assignment_outcome_v2",
    "assemble_assignment_outcomes",
    "validate_functional_outcomes",
]
