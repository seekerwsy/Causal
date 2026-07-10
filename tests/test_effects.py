from secaware.analysis.effects import estimate_effects
from secaware.schema.results import PairResult


def test_all_insecure_to_secure_pairs_confirm_risk_down_effect() -> None:
    pairs = [
        PairResult(
            pair_id=f"pair_p{i}_h1_mock_1",
            prompt_id=f"p{i}",
            hypothesis_id="h1",
            model_id="mock",
            seed_id=1,
            factor_type="path_normalization",
            expected_direction="risk_down",
            same_task_valid=True,
            target_changed=True,
            side_effect=False,
            functional_observed=True,
            functional_counterfactual=True,
            security_observed="insecure",
            security_counterfactual="secure",
            delta=-1,
            flip_type="secure_flip",
            eligible_per_protocol=True,
            eligible_itt=True,
            failure_reason=None,
        )
        for i in range(10)
    ]

    effects = estimate_effects(
        pairs,
        bootstrap_samples=50,
        min_eligible_pairs=2,
        min_flip_rate=0.05,
        random_seed=123,
    )

    assert len(effects) == 1
    effect = effects[0]
    assert effect.per_protocol_risk_difference < 0
    assert effect.secure_flip_rate > 0
    assert effect.status == "confirmed"


def test_confirmed_effect_does_not_report_non_blocking_failure_reason() -> None:
    pairs = [
        PairResult(
            pair_id=f"pair_p{i}_h1_mock_1",
            prompt_id=f"p{i}",
            hypothesis_id="h1",
            model_id="mock",
            seed_id=1,
            factor_type="path_normalization",
            expected_direction="risk_down",
            same_task_valid=True,
            target_changed=True,
            side_effect=False,
            functional_observed=True,
            functional_counterfactual=True,
            security_observed="insecure",
            security_counterfactual="secure",
            delta=-1,
            flip_type="secure_flip",
            eligible_per_protocol=True,
            eligible_itt=True,
            failure_reason=None,
        )
        for i in range(2)
    ]
    pairs.append(
        PairResult(
            pair_id="pair_safe_h1_mock_1",
            prompt_id="safe",
            hypothesis_id="h1",
            model_id="mock",
            seed_id=1,
            factor_type="path_normalization",
            expected_direction="risk_down",
            same_task_valid=True,
            target_changed=False,
            side_effect=False,
            functional_observed=True,
            functional_counterfactual=True,
            security_observed="secure",
            security_counterfactual="secure",
            delta=0,
            flip_type="no_flip",
            eligible_per_protocol=False,
            eligible_itt=True,
            failure_reason="target_not_changed",
        )
    )

    effect = estimate_effects(
        pairs,
        bootstrap_samples=20,
        min_eligible_pairs=2,
        random_seed=123,
    )[0]

    assert effect.status == "confirmed"
    assert effect.main_failure_reason is None
