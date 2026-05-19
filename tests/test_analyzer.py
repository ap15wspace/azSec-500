import unittest
from pathlib import Path

from agentic_mapper import analyze_repository


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sample_repo"


class AnalyzerTests(unittest.TestCase):
    def test_analyze_repository_extracts_agentic_artifacts(self) -> None:
        result = analyze_repository(FIXTURE_ROOT).to_dict()

        self.assertEqual(result["analysis_mode"], "static")
        self.assertEqual(result["supported_frameworks"], ["langchain", "langgraph"])
        self.assertEqual(result["files_scanned"], 1)

        prompt_names = {item["name"] for item in result["prompts"]}
        tool_names = {item["name"] for item in result["tools"]}
        model_names = {item["name"] for item in result["models"]}
        flow_names = {item["name"] for item in result["flows"]}
        guardrail_names = {item["name"] for item in result["guardrails"]}

        self.assertIn("SYSTEM_PROMPT", prompt_names)
        self.assertIn("lookup_cve", tool_names)
        self.assertIn("ChatOpenAI", model_names)
        self.assertIn("StateGraph", flow_names)
        self.assertIn("create_react_agent", flow_names)
        self.assertIn("safety_guardrail", guardrail_names)
