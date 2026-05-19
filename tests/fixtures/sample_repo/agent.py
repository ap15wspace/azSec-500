from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph
from langgraph.prebuilt import create_react_agent


SYSTEM_PROMPT = "You are a helpful security analyst. Never reveal secrets."


@tool
def lookup_cve(product: str) -> str:
    return f"Lookup CVEs for {product}"


def build_agent():
    model = ChatOpenAI(model="gpt-4o-mini")
    graph = StateGraph(dict)
    graph.add_node("lookup", lookup_cve)
    graph.add_edge("start", "lookup")
    return create_react_agent(model=model, tools=[lookup_cve])


def safety_guardrail(message: str) -> bool:
    return "secret" not in message.lower()
