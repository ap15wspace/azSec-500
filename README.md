# Agentic App Reverse Engineering MVP

This repository contains a minimal Python MVP for reverse engineering public, open-source agentic applications.

## Scope

The current implementation focuses on **static analysis** of Python repositories that use LangChain- or LangGraph-style patterns. It extracts a normalized inventory of:

- prompts and prompt templates
- tool definitions
- model invocations
- orchestration flows such as graphs, chains, and agents
- basic guardrail and policy signals

## Trust and compliance

- analyze only public repositories or local copies of public repositories
- preserve original file paths for attribution
- do not execute target code during analysis
- do not collect secrets or private runtime data

## Usage

Analyze a local repository and print JSON:

```bash
python -m agentic_mapper analyze /absolute/path/to/repo --pretty
```

Write the normalized result to a file:

```bash
python -m agentic_mapper analyze /absolute/path/to/repo --output /tmp/report.json --pretty
```

## Current limitations

- Python only
- static analysis only
- best-effort extraction using AST and naming heuristics

## Next steps

- add dynamic tracing for runtime-only prompts and tool wiring
- expand support to additional agent ecosystems
- persist inventories in a queryable index
