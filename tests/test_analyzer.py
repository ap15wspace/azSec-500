from pathlib import Path

from agentic_mapper import analyze_repository


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sample_repo"


def test_analyze_repository_extracts_agentic_artifacts() -> None:
    result = analyze_repository(FIXTURE_ROOT).to_dict()

    assert result["analysis_mode"] == "static"
    assert result["supported_frameworks"] == ["langchain", "langgraph"]
    assert result["files_scanned"] == 1

    prompt_names = {item["name"] for item in result["prompts"]}
    tool_names = {item["name"] for item in result["tools"]}
    model_names = {item["name"] for item in result["models"]}
    flow_names = {item["name"] for item in result["flows"]}
    guardrail_names = {item["name"] for item in result["guardrails"]}

    assert "SYSTEM_PROMPT" in prompt_names
    assert "lookup_cve" in tool_names
    assert "ChatOpenAI" in model_names
    assert "StateGraph" in flow_names
    assert "create_react_agent" in flow_names
    assert "safety_guardrail" in guardrail_names
