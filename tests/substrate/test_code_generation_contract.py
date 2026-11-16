"""Generation output contract: a malformed or off-target patch is a code-validity failure, never a silent repair."""

import json

import jsonschema
import pytest

from prompt_mechanism_study.experiment.code_generation import (
    PATCH_OUTPUT_CONTRACT,
    extract_single_code_block,
    parse_candidate_patch,
    splice_target_unit_code,
)

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


def test_deterministic_code_splicing_preserves_surrounding_scaffold_and_classifies_failures():
    scaffold = (
        'import subprocess\n\n'
        'HELPER_CONSTANT = "kept"\n\n'
        'def run_cmd(host):\n'
        '    return subprocess.run(host, shell=True)\n\n'
        'def trailing():\n'
        '    return HELPER_CONSTANT\n'
    )
    fenced_ok = (
        '```python\n'
        'def run_cmd(host):\n'
        '    return subprocess.run(["ping", "-c", "1", host], shell=False)\n'
        '```\n'
    )
    res = splice_target_unit_code(scaffold, fenced_ok, target_symbol='run_cmd')
    assert res['code_status'] == 'valid' and res['terminal_reason'] is None
    assert 'HELPER_CONSTANT = "kept"' in res['spliced_code']
    assert 'def trailing():' in res['spliced_code']
    assert 'shell=False' in res['spliced_code']

    assert splice_target_unit_code(scaffold, '   ', target_symbol='run_cmd')['code_status'] == 'no_code'
    assert splice_target_unit_code(scaffold, '```python\n   \n```', target_symbol='run_cmd')['code_status'] == 'no_code'
    diff_reply = '```python\n--- a/pkg.py\n+++ b/pkg.py\n@@ -1 +1 @@\n-a\n+b\n```'
    assert splice_target_unit_code(scaffold, diff_reply, target_symbol='run_cmd')['terminal_reason'] == 'patch_output_rejected'
    multi = '```python\ndef run_cmd(host):\n    pass\n```\n\n```python\ndef run_cmd(host):\n    pass\n```'
    assert extract_single_code_block(multi)[1] == 'ambiguous_code_blocks'
    assert splice_target_unit_code(scaffold, '```javascript\nfunction run_cmd() {}\n```', target_symbol='run_cmd')['code_status'] == 'invalid'
    assert splice_target_unit_code(scaffold, 'def run_cmd(host):\n    return (', target_symbol='run_cmd')['code_status'] == 'invalid'
    assert splice_target_unit_code(scaffold, 'def other_fn(host):\n    return 1\n', target_symbol='run_cmd')['terminal_reason'] == 'missing_or_duplicate_target_symbol'
