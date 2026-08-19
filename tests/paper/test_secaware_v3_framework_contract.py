from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md"
PAPER_AGENTS = ROOT / "paper/AGENTS.md"
SKILL = ROOT / ".agents/skills/secaware-fse-paper/SKILL.md"
BOUNDARIES = ROOT / ".agents/skills/secaware-fse-paper/references/causal-boundaries.md"


class SecAwareV3FrameworkContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = SPEC.read_text(encoding="utf-8")

    def test_two_regimes_and_bridge_are_explicit(self) -> None:
        required = (
            "## 4. Two Explicit Data-Generating Regimes",
            "X_{if}^{0}",
            "X_{if}^{A,R}",
            "Gamma_{h,A,R}",
            "## 4.3 Intervention bridge",
            "h=(C_q,f,a,Q_h,Y)",
        )
        for value in required:
            self.assertIn(value, self.spec)

    def test_context_is_not_the_actionable_treatment(self) -> None:
        required = (
            "ContextQuerySpec",
            "ActionableFeatureSpec",
            "CompositeHypothesisPattern",
            "WITHOUT_GUARD",
            "guard-independent context",
            "exactly one actionable leaf feature",
            "if and only if `s^C_hi=PRESENT`",
            "`ADD`: `s^f_hi=ABSENT`",
            "`REMOVE`: `s^f_hi=PRESENT`",
            "neutral counterpart",
        )
        for value in required:
            self.assertIn(value, self.spec)

    def test_randomization_and_cluster_hierarchy_is_locked(self) -> None:
        required = (
            "request_randomness_slot",
            "(semantic_task_cluster_id,",
            "realization_spec_id,",
            "task_realization_bundle_id,",
            "arm_protocol_id)",
            "Mutation of",
            "semantic_task_cluster_id",
            "nested cluster bootstrap",
            "no cross-request interference",
        )
        for value in required:
            self.assertIn(value, self.spec)

    def test_outcome_and_estimator_are_decomposed(self) -> None:
        required = (
            "oracle-evaluable secure-code yield",
            "Y_C=I",
            "Y_E=I",
            "Y_{\\mathrm{joint}}",
            "D_{hmc}^{Y}",
            "\\widehat\\tau_{hm}^Y",
            "Manski-style arm bounds",
        )
        for value in required:
            self.assertIn(value, self.spec)

    def test_selector_and_realization_rules_are_complete(self) -> None:
        required = (
            "CandidateSkeleton",
            "RealizationPolicySpec",
            "RealizationSpecRecord",
            "TaskRealizationBundleRecord",
            "CandidateUniverseManifest",
            "SelectionFreezeManifest",
            "Selector-only comparison",
            "Representation comparison",
            "strict\\ confirmed\\ yield@K",
            "The support of `Q_h` is immutable",
            "max_r |tau_{hmr}-tau_{hm}|",
            "leave-one-realization-out",
            "context_query_catalog_sha256",
            "`SANITIZER` is not persisted",
        )
        for value in required:
            self.assertIn(value, self.spec)

    def test_main_scope_has_three_rqs_and_appendix_only_sensitivities(self) -> None:
        main_rq_section = self.spec.split("## 16. Main-Paper Research Questions", 1)[1].split(
            "## 17.", 1
        )[0]
        self.assertEqual(len(re.findall(r"> \*\*RQ[1-3]\.", main_rq_section)), 3)
        self.assertNotIn("RQ4.", main_rq_section)
        appendix_scope = self.spec.split("## 17. JCI, RFCI, and Expert Study Scope", 1)[1].split(
            "## 18.", 1
        )[0]
        self.assertIn("appendix", appendix_scope.casefold())
        self.assertIn("former expert-perception RQ4 is removed", appendix_scope)

    def test_project_paper_guidance_points_to_the_successor(self) -> None:
        successor = SPEC.name
        self.assertIn(successor, SKILL.read_text(encoding="utf-8"))
        self.assertIn(successor, BOUNDARIES.read_text(encoding="utf-8"))
        guidance = PAPER_AGENTS.read_text(encoding="utf-8")
        self.assertIn("2026-08-20 context-conditioned intervention-policy successor", guidance)
        self.assertIn("semantic_task_cluster_id", guidance)
        self.assertIn("oracle-evaluable secure-code yield", guidance)


if __name__ == "__main__":
    unittest.main()
