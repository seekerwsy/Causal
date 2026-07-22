from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PAPER = ROOT / "paper" / "fse2027" / "secaware-fse2027-draft.tex"
PAPER_AGENTS = ROOT / "paper" / "AGENTS.md"
SKILL = ROOT / ".agents" / "skills" / "secaware-fse-paper" / "SKILL.md"
SKILL_ROOT = SKILL.parent


def _normalized(path: Path) -> str:
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8")).strip()


class SecAwareFsePaperContractTest(unittest.TestCase):
    def test_project_paper_guidance_and_skill_are_discoverable(self) -> None:
        self.assertTrue(PAPER_AGENTS.is_file())
        self.assertTrue(SKILL.is_file())
        self.assertTrue((SKILL_ROOT / "agents" / "openai.yaml").is_file())
        self.assertTrue((SKILL_ROOT / "references" / "causal-boundaries.md").is_file())
        self.assertTrue((SKILL_ROOT / "references" / "fse-2027-checklist.md").is_file())

        skill = SKILL.read_text(encoding="utf-8")
        self.assertTrue(skill.startswith("---\nname: secaware-fse-paper\n"))
        self.assertIn("description: Use when", skill)
        self.assertIn("2026-07-22-paper-research-questions-design.md", skill)
        self.assertIn("audit", skill)
        self.assertIn("revise", skill)
        self.assertIn("results-backfill", skill)
        self.assertIn("presubmit", skill)

    def test_manuscript_uses_approved_research_questions(self) -> None:
        manuscript = _normalized(PAPER)
        expected = (
            "RQ1. How effectively can different methods discover and confirm "
            "security-relevant prompt-side mechanisms in LLM code generation?",
            "RQ2. How do SecAware's structured representation and causal analysis "
            "components contribute to mechanism discovery and confirmation?",
            "RQ3. Which prompt-side defensive interventions effectively reduce "
            "insecure code generation?",
            "RQ4. How do security experts rate and rank the perceived quality and "
            "usefulness of explanations produced by different methods?",
        )
        for research_question in expected:
            self.assertIn(research_question, manuscript)

    def test_manuscript_uses_prompt_only_fci_and_randomized_itt_contract(self) -> None:
        manuscript = PAPER.read_text(encoding="utf-8")
        normalized = re.sub(r"\s+", " ", manuscript)

        required_phrases = (
            r"\documentclass[acmsmall,screen,review,anonymous]{acmart}",
            "causal-learn",
            "G-square",
            "task-cluster",
            "TARGET_PATCH",
            "NOOP_REWRITE",
            "LENGTH_MATCHED_PLACEBO",
            "GENERIC_SECURITY_REMINDER",
            "JCI",
            "RFCI",
            "confirmed yield at $K$",
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
        )
        for phrase in stale_phrases:
            self.assertNotIn(phrase.casefold(), normalized.casefold())

    def test_data_availability_follows_conclusion(self) -> None:
        manuscript = PAPER.read_text(encoding="utf-8")
        conclusion = manuscript.index(r"\section{Conclusion}")
        data_availability = manuscript.index(r"\section{Data Availability}")
        end = manuscript.index(r"\end{document}")
        self.assertLess(conclusion, data_availability)
        self.assertLess(data_availability, end)


if __name__ == "__main__":
    unittest.main()
