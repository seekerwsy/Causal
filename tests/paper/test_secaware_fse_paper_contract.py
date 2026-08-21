from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAPER = ROOT / "paper" / "fse2027" / "secaware-fse2027-draft.tex"
ROOT_AGENTS = ROOT / "AGENTS.md"
PAPER_AGENTS = ROOT / "paper" / "AGENTS.md"


def _normalized(path: Path) -> str:
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8")).strip()


class SecAwareFsePaperContractTest(unittest.TestCase):
    def test_project_and_paper_guidance_are_discoverable(self) -> None:
        self.assertTrue(ROOT_AGENTS.is_file())
        self.assertTrue(PAPER_AGENTS.is_file())

        project_guidance = ROOT_AGENTS.read_text(encoding="utf-8")
        paper_guidance = PAPER_AGENTS.read_text(encoding="utf-8")
        self.assertIn("A Reviewable Research Artifact", project_guidance)
        self.assertIn("exactly one active, documented path", project_guidance)
        self.assertIn("Research and Reporting Integrity", project_guidance)
        self.assertIn(
            "2026-08-20-context-conditioned-intervention-policy-framework.md",
            paper_guidance,
        )
        self.assertIn("assigned-arm ITT", paper_guidance)

    def test_manuscript_uses_approved_research_questions(self) -> None:
        manuscript = _normalized(PAPER)
        expected = (
            (
                "RQ1. How effectively can different methods prioritize prompt "
                "interventions that generalize to held-out tasks?"
            ),
            (
                "RQ3. Which prompt-side security interventions reliably improve "
                "secure code generation?"
            ),
        )
        for research_question in expected:
            self.assertIn(research_question, manuscript)

        self.assertRegex(
            manuscript,
            re.escape(r"RQ2. How do \model's structured representation and causal ")
            + re.escape("prioritization contribute to successful intervention selection?"),
        )
        main_rqs = re.findall(r"\\textbf\{RQ\d+\.[^}]+\}", manuscript)
        self.assertEqual(len(main_rqs), 3)
        self.assertNotIn("RQ4.", manuscript)
        self.assertNotIn(
            "discover and confirm security-relevant prompt-side mechanisms",
            manuscript.casefold(),
        )
        self.assertNotIn(
            "defensive interventions effectively reduce insecure code generation",
            manuscript.casefold(),
        )

    def test_manuscript_uses_successor_selector_and_randomized_itt_contract(self) -> None:
        manuscript = PAPER.read_text(encoding="utf-8")
        normalized = re.sub(r"\s+", " ", manuscript)

        required_phrases = (
            r"\documentclass[acmsmall,screen,review,anonymous]{acmart}",
            "causal-learn",
            "G-square",
            r"\texttt{semantic\_task\_cluster\_id}",
            "shared candidate universe",
            "strict confirmed yield at $K$",
            "paired selector-utility differences",
            "native-system track",
            "secondary end-to-end",
            "representation comparison",
            "end-to-end comparison",
            "not a pure selector comparison",
            "TARGET_PATCH",
            "NOOP_REWRITE",
            "LENGTH_MATCHED_PLACEBO",
            "GENERIC_SECURITY_REMINDER",
            "TARGET_REMOVE",
            "NOOP_RETAIN",
            "oracle-evaluable secure-code yield",
            "key practical secondary outcome",
            "$X^0$",
            "$X^{A,R}$",
            "Randomized arm $A$",
            "$C_q$",
            "exactly one actionable feature",
        )
        for phrase in required_phrases:
            self.assertIn(phrase, normalized)

        stale_phrases = (
            "primary per-protocol",
            "ITT sensitivity",
            "Bandit as the current default",
            "conditional flip success",
            "paired counterfactual",
            "strict-confirmed precision",
            "Relaxed directional replication",
            "the confirm pool is filtered",
            "two-by-two",
            "primary secure-and-functional",
            "unique prompt mechanism",
            "code-side mediation",
        )
        for phrase in stale_phrases:
            self.assertNotIn(phrase.casefold(), normalized.casefold())

    def test_optional_analyses_and_expert_study_are_appendix_only(self) -> None:
        manuscript = PAPER.read_text(encoding="utf-8")
        main_text, appendix = manuscript.split(r"\appendix", maxsplit=1)

        optional_terms = (
            "JCI",
            "RFCI",
            "implementation marker",
            "treatment fidelity",
            "per-protocol",
            "human-study",
            "expert-perception",
        )
        for term in optional_terms:
            self.assertNotIn(term.casefold(), main_text.casefold())

        appendix_requirements = (
            "JCI",
            "RFCI",
            "implementation markers",
            "treatment fidelity",
            "per-protocol",
            "cannot promote",
            "separately versioned optional expert study",
        )
        for phrase in appendix_requirements:
            self.assertIn(phrase.casefold(), appendix.casefold())

    def test_primary_outcome_and_atomic_operations_are_not_substituted(self) -> None:
        manuscript = _normalized(PAPER)
        self.assertIn(
            "The primary oracle-evaluable secure-code yield is "
            r"$Y_CY_E I(\text{Oracle secure})$",
            manuscript,
        )
        self.assertIn(
            "secure-and-functional joint success",
            manuscript,
        )
        self.assertIn(
            "ADD and REMOVE remain separate candidate slots, hypotheses, protocols, "
            "contrasts, multiplicity coordinates, and evidence",
            manuscript,
        )
        self.assertNotIn("Functionality is a mediator", manuscript)

    def test_placeholders_are_preserved_without_fabricated_results(self) -> None:
        manuscript = PAPER.read_text(encoding="utf-8")
        self.assertGreaterEqual(manuscript.count(r"\resultslot"), 2)
        self.assertGreaterEqual(manuscript.count("--"), 100)

    def test_data_availability_follows_conclusion(self) -> None:
        manuscript = PAPER.read_text(encoding="utf-8")
        conclusion = manuscript.index(r"\section{Conclusion}")
        data_availability = manuscript.index(r"\section{Data Availability}")
        end = manuscript.index(r"\end{document}")
        self.assertLess(conclusion, data_availability)
        self.assertLess(data_availability, end)


if __name__ == "__main__":
    unittest.main()
