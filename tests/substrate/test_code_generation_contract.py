"""Generation output contract: a malformed or off-target patch is a code-validity failure, never a silent repair."""

import json

import jsonschema
import pytest

from prompt_mechanism_study.experiment.code_generation import PATCH_OUTPUT_CONTRACT, parse_candidate_patch

TARGET, DIGEST = 'pkg/module.py', 'b' * 64


def _response(**overrides):
    record = dict(contract=PATCH_OUTPUT_CONTRACT, target_path=TARGET, source_sha256=DIGEST,
                  unified_diff='--- a/pkg/module.py\n+++ b/pkg/module.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n')
    record.update(overrides)
    return json.dumps(record)


def test_patch_contract_accepts_exact_declared_target_only():
    assert parse_candidate_patch(_response(), TARGET, DIGEST)['target_path'] == TARGET
    for bad in (_response(target_path='other.py'), _response(source_sha256='c' * 64), _response(unified_diff=''),
                _response(extra='prose')):
        with pytest.raises(jsonschema.ValidationError):
            parse_candidate_patch(bad, TARGET, DIGEST)


def test_patch_contract_rejects_duplicate_keys():
    duplicated = _response()[:-1] + f', "target_path": "{TARGET}"}}'
    with pytest.raises(ValueError, match='Duplicate JSON object key'):
        parse_candidate_patch(duplicated, TARGET, DIGEST)
