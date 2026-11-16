"""Natural-task design invariants: fold-nested assignment (D1) and ITT endpoint separation."""

import numpy as np
import pytest

from prompt_mechanism_study.experiment.assignment import assign_fold_nested, task_unit_folds
from prompt_mechanism_study.experiment.outcomes import derive_outcomes
from prompt_mechanism_study.measurement.evaluate import (
    CodeStatus,
    FunctionalStatus,
    Measurement,
    MeasurementLedger,
    OracleStatus,
)
from prompt_mechanism_study.verification.assignment import verify_fold_nested_assignment

UNITS = [f'task-{index:03d}' for index in range(37)]


def test_assignment_is_within_fold_balanced_deterministic_and_independently_replayed():
    record = assign_fold_nested(list(reversed(UNITS)), folds=4, seed=2026111641)
    assert record == assign_fold_nested(UNITS, folds=4, seed=2026111641)
    rows = record['assignments']
    assert [row['task_unit_id'] for row in rows] == sorted(UNITS)
    assert [row['fold'] for row in rows] == task_unit_folds(len(UNITS), 4).tolist()
    for fold in range(4):
        arms = [row['arm'] for row in rows if row['fold'] == fold]
        assert len(arms) // 2 <= sum(arms) <= len(arms) // 2 + len(arms) % 2
    assert verify_fold_nested_assignment(record)['status'] == 'VERIFIED'

    tampered = dict(record, assignments=[dict(row) for row in rows])
    tampered['assignments'][0]['arm'] ^= 1
    with pytest.raises(AssertionError):
        verify_fold_nested_assignment(tampered)


def test_assignment_has_exact_half_marginals_and_rejects_duplicate_units():
    treated = np.mean(
        [[row['arm'] for row in assign_fold_nested(UNITS, folds=4, seed=seed)['assignments']] for seed in range(2000)],
        axis=0,
    )
    assert np.all(np.abs(treated - 0.5) < 0.06)
    with pytest.raises(ValueError, match='deduplicated'):
        assign_fold_nested([*UNITS, UNITS[0]], folds=4, seed=1)


def test_endpoints_never_coerce_unknown_into_insecure_or_absent():
    digest = 'a' * 64
    valid = dict(code_status=CodeStatus.VALID, generator_evidence_sha256=digest, code_sha256=digest,
                 oracle_evidence_sha256=digest, functional_evidence_sha256=digest)
    ledger = MeasurementLedger('study', 'randomization', 'adapter', (
        Measurement('a-secure', oracle_status=OracleStatus.SECURE, functional_status=FunctionalStatus.PASS, **valid),
        Measurement('b-unknown', oracle_status=OracleStatus.UNKNOWN, functional_status=FunctionalStatus.UNKNOWN, **valid),
        Measurement('c-insecure', oracle_status=OracleStatus.INSECURE, functional_status=FunctionalStatus.PASS, **valid),
        Measurement('d-nocode', CodeStatus.NO_CODE, OracleStatus.NOT_RUN, FunctionalStatus.NOT_RUN, digest,
                    terminal_reason='empty response'),
    ))
    outcomes = {item.assignment_id: item for item in derive_outcomes(ledger)}
    assert (outcomes['a-secure'].secure_yield, outcomes['a-secure'].joint) == (1, 1)
    unknown = outcomes['b-unknown']
    assert (unknown.code_valid, unknown.oracle_evaluable, unknown.secure_yield) == (1, 0, 0)
    assert unknown.latent_secure_upper == 1 and unknown.functionality is None and unknown.joint is None
    assert (outcomes['c-insecure'].oracle_evaluable, outcomes['c-insecure'].joint) == (1, 0)
    # Terminal (no-code) assignments stay in the ITT denominator with zero yields.
    assert len(outcomes) == 4 and outcomes['d-nocode'].terminal_status == 'no_code'
