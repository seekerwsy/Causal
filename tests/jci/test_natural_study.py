"""End-to-end offline natural-task Stage I -> Stage II pipeline and independent verification tests."""

import shutil

import pytest

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.cli import main as cli_main
from prompt_mechanism_study.verification.natural_study import verify_natural_study


def test_natural_task_smoke_pipeline_and_independent_verification(tmp_path):
    out_dir = tmp_path / 'natural-smoke'
    assert cli_main(['study', 'natural-smoke', str(out_dir)]) == 0
    assert cli_main(['study', 'verify', str(out_dir)]) == 0

    summary = read_json(out_dir / 'summary' / 'result.json')
    verified = read_json(out_dir / 'verification' / 'result.json')
    overall = summary['endpoints']['overall']

    assert summary['study_mode'] == 'natural_task'
    assert summary['formal_claim_allowed'] is False
    assert summary['new_provider_calls'] == 0
    assert summary['assigned_n'] == overall['assigned_n'] == 24
    assert summary['reliability_gate_passed'] is True
    # Invalid generation stays in the ITT denominator; unknown oracle is never coerced.
    assert overall['code_valid_count'] < overall['assigned_n']
    assert overall['oracle_evaluable_count'] < overall['code_valid_count']
    assert overall['unknown_oracle_count'] >= 1
    assert verified['status'] == 'VERIFIED' and verified['assigned_n'] == 24

    # Re-hashed tampered summary must be rejected by independent verification.
    forged = dict(summary, jci_guidance_status='adverse_warning' if summary['jci_guidance_status'] != 'adverse_warning' else 'practically_null')
    shutil.rmtree(out_dir / 'summary')
    shutil.rmtree(out_dir / 'verification')
    write_bundle(out_dir / 'summary', {'result.json': forged})
    with pytest.raises(AssertionError):
        verify_natural_study(out_dir)
