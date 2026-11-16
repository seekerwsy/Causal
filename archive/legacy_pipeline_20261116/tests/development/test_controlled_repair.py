import json
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json, verify_bundle
from prompt_mechanism_study.tsg.prepared_prompts import (
    submit_controlled_preparation, submit_controlled_review,
)
from prompt_mechanism_study.verification.controlled import verify_controlled_repair


REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / 'data/method/controlled-semantic-20260930'


def test_complete_actual_preparation_submission(tmp_path):
    public = SOURCE / 'main-public/E-grep-096-TSG.json'
    prepared = SOURCE / 'main-prepared/E-grep-096-TSG.json'
    output = tmp_path / 'submitted.json'
    assert submit_controlled_preparation(public, prepared, output)['status'] == 'SUBMITTED'
    assert read_json(output) == read_json(prepared)
    with pytest.raises(FileExistsError):
        submit_controlled_preparation(public, prepared, output)
    incomplete = read_json(prepared)
    incomplete['candidates'][0]['versions'].pop()
    submission = tmp_path / 'incomplete.json'
    submission.write_text(json.dumps(incomplete), encoding='utf-8')
    with pytest.raises(ValueError, match='完整提交'):
        submit_controlled_preparation(public, submission, tmp_path / 'rejected.json')
    assert not (tmp_path / 'rejected.json').exists()


def test_complete_actual_review_and_atomic_flip(tmp_path):
    source = SOURCE / 'main-blind-reviews/84ec2d50db27006a56c728e0/input.json'
    reviewed = SOURCE / 'main-qualified/E-grep-096-TSG/review.json'
    output = tmp_path / 'reviewed.json'
    assert submit_controlled_review(source, reviewed, output)['status'] == 'SUBMITTED'
    assert read_json(output) == read_json(reviewed)
    incomplete = read_json(reviewed)
    incomplete['reviews'][0]['versions'].pop()
    submission = tmp_path / 'incomplete-review.json'
    submission.write_text(json.dumps(incomplete), encoding='utf-8')
    with pytest.raises(ValueError, match='全部实际表达版本'):
        submit_controlled_review(source, submission, tmp_path / 'rejected-review.json')
    incorrect = read_json(reviewed)
    incorrect['reviews'][0]['versions'][0]['states_after'] = incorrect['reviews'][0]['versions'][0]['states_before']
    submission.write_text(json.dumps(incorrect), encoding='utf-8')
    with pytest.raises(ValueError, match='仅翻转目标'):
        submit_controlled_review(source, submission, tmp_path / 'rejected-review.json')
    assert not (tmp_path / 'rejected-review.json').exists()


def test_independent_actual_repair_results(tmp_path):
    results = REPO / 'results/controlled-repair-20261007'
    verify_controlled_repair(REPO / 'data/method/controlled-repair-20261007/observer-inputs',
        results / 'observer-check', results / 'safe-decisions', tmp_path / 'verification', repository_root=REPO)
    verify_bundle(tmp_path / 'verification')
    record = read_json(tmp_path / 'verification/verification.json')
    assert record['status'] == 'PASSED' and record['real_probes'] == 168
    assert sum(record['action_counts'].values()) == record['decision_tasks'] == 400
