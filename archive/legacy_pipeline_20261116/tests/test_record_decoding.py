from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.experiment.reviewer_fixture import ReviewerSmokeFixture
from prompt_mechanism_study.verification.integrity import _decode_target_value


@pytest.mark.parametrize('change', ('missing', 'extra', 'boolean_integer', 'null_extension', 'tuple_length'))
def test_saved_record_rejects_nonexact_fields_and_types(change):
    path = Path(__file__).resolve().parents[1] / 'src/fixtures/reviewer_smoke.json'
    record = read_json(path)
    if change == 'missing':
        del record['generation_call_limit']
    elif change == 'extra':
        record['extra_field'] = 0
    elif change == 'boolean_integer':
        record['atomic_total_block_slots'] = True
    elif change == 'null_extension':
        record['atomic_universe']['source_binding_sha256'] = None
    else:
        record['generation_responses'][0].pop()
    with pytest.raises(ValueError):
        _decode_target_value(record, ReviewerSmokeFixture, path.name)
