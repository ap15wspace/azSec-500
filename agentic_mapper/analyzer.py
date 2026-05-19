from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


PROMPT_NAME_HINTS = (
    "prompt",
    "template",
    "instruction",
    "system_message",
    "message",
)
GUARDRAIL_NAME_HINTS = ("guardrail", "validator", "moderation", "policy", "safety", "filter")
MODEL_CALL_HINTS = {
    "ChatOpenAI",
    "AzureChatOpenAI",
    "OpenAI",
    "ChatAnthropic",
    "ChatGoogleGenerativeAI",
    "init_chat_model",
}
FLOW_CALL_HINTS = {
    "StateGraph": "graph",
    "MessageGraph": "graph",
    "create_react_agent": "agent",
    "AgentExecutor": "agent_executor",
    "LLMChain": "chain",
    "SequentialChain": "chain",
    "RunnableSequence": "chain",
    "ToolNode": "tool_node",
}
GRAPH_OPERATION_HINTS = {"add_node", "add_edge", "add_conditional_edges", "compile"}


@dataclass
class Artifact:
    kind: str
    name: str
    file_path: str
    line: int
    details: dict[str, object] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    repository_root: str
    analysis_mode: str
    supported_frameworks: list[str]
    files_scanned: int
    prompts: list[Artifact]
    tools: list[Artifact]
    models: list[Artifact]
    flows: list[Artifact]
    guardrails: list[Artifact]
    issues: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "repository_root": self.repository_root,
            "analysis_mode": self.analysis_mode,
            "supported_frameworks": self.supported_frameworks,
            "files_scanned": self.files_scanned,
            "prompts": [asdict(item) for item in self.prompts],
            "tools": [asdict(item) for item in self.tools],
            "models": [asdict(item) for item in self.models],
            "flows": [asdict(item) for item in self.flows],
            "guardrails": [asdict(item) for item in self.guardrails],
            "issues": self.issues,
        }


class RepositoryAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path: Path, source: str) -> None:
        self.file_path = file_path
        self.source = source
        self.prompts: list[Artifact] = []
        self.tools: list[Artifact] = []
        self.models: list[Artifact] = []
        self.flows: list[Artifact] = []
        self.guardrails: list[Artifact] = []
        self.frameworks: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._record_framework(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._record_framework(node.module)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        text = _literal_string(node.value)
        for target in node.targets:
            for target_name in _iter_target_names(target):
                if text and _looks_like_prompt_name(target_name):
                    self.prompts.append(
                        Artifact(
                            kind="assignment",
                            name=target_name,
                            file_path=_relative_file_path(self.file_path),
                            line=node.lineno,
                            details={"text": text},
                        )
                    )
                if _contains_hint(target_name, GUARDRAIL_NAME_HINTS):
                    self.guardrails.append(
                        Artifact(
                            kind="assignment",
                            name=target_name,
                            file_path=_relative_file_path(self.file_path),
                            line=node.lineno,
                            details={"text": text or ""},
                        )
                    )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        decorator_names = [_callable_name(decorator) for decorator in node.decorator_list]
        for decorator_name in decorator_names:
            if "tool" in decorator_name.lower():
                self.tools.append(
                    Artifact(
                        kind="function",
                        name=node.name,
                        file_path=_relative_file_path(self.file_path),
                        line=node.lineno,
                        details={"decorator": decorator_name},
                    )
                )
        if _contains_hint(node.name, GUARDRAIL_NAME_HINTS):
            self.guardrails.append(
                Artifact(
                    kind="function",
                    name=node.name,
                    file_path=_relative_file_path(self.file_path),
                    line=node.lineno,
                    details={},
                )
            )
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if _contains_hint(node.name, GUARDRAIL_NAME_HINTS):
            self.guardrails.append(
                Artifact(
                    kind="class",
                    name=node.name,
                    file_path=_relative_file_path(self.file_path),
                    line=node.lineno,
                    details={},
                )
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _callable_name(node.func)
        self._record_call_based_artifacts(call_name, node)
        self.generic_visit(node)

    def _record_framework(self, module_name: str) -> None:
        lowered = module_name.lower()
        if lowered.startswith("langchain"):
            self.frameworks.add("langchain")
        if lowered.startswith("langgraph"):
            self.frameworks.add("langgraph")

    def _record_call_based_artifacts(self, call_name: str, node: ast.Call) -> None:
        if call_name in MODEL_CALL_HINTS:
            self.models.append(
                Artifact(
                    kind="call",
                    name=call_name,
                    file_path=_relative_file_path(self.file_path),
                    line=node.lineno,
                    details={"arguments": _summarize_call_arguments(node)},
                )
            )

        flow_kind = FLOW_CALL_HINTS.get(call_name)
        if flow_kind:
            self.flows.append(
                Artifact(
                    kind=flow_kind,
                    name=call_name,
                    file_path=_relative_file_path(self.file_path),
                    line=node.lineno,
                    details={"arguments": _summarize_call_arguments(node)},
                )
            )

        if call_name in GRAPH_OPERATION_HINTS:
            self.flows.append(
                Artifact(
                    kind="graph_operation",
                    name=call_name,
                    file_path=_relative_file_path(self.file_path),
                    line=node.lineno,
                    details={"arguments": _summarize_call_arguments(node)},
                )
            )

        lowered = call_name.lower()
        if "prompttemplate" in lowered or lowered in {"systemmessage", "humanmessage"}:
            text = _extract_prompt_text_from_call(node)
            self.prompts.append(
                Artifact(
                    kind="call",
                    name=call_name,
                    file_path=_relative_file_path(self.file_path),
                    line=node.lineno,
                    details={"text": text},
                )
            )

        if _contains_hint(call_name, GUARDRAIL_NAME_HINTS):
            self.guardrails.append(
                Artifact(
                    kind="call",
                    name=call_name,
                    file_path=_relative_file_path(self.file_path),
                    line=node.lineno,
                    details={"arguments": _summarize_call_arguments(node)},
                )
            )


def analyze_repository(repository_root: str | Path) -> AnalysisResult:
    root = Path(repository_root).resolve()
    prompts: list[Artifact] = []
    tools: list[Artifact] = []
    models: list[Artifact] = []
    flows: list[Artifact] = []
    guardrails: list[Artifact] = []
    frameworks: set[str] = set()
    issues: list[str] = []
    files_scanned = 0

    for file_path in _iter_python_files(root):
        files_scanned += 1
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(file_path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            issues.append(f"{file_path.relative_to(root)}: {exc}")
            continue

        analyzer = RepositoryAnalyzer(file_path.relative_to(root), source)
        analyzer.visit(tree)
        prompts.extend(analyzer.prompts)
        tools.extend(analyzer.tools)
        models.extend(analyzer.models)
        flows.extend(analyzer.flows)
        guardrails.extend(analyzer.guardrails)
        frameworks.update(analyzer.frameworks)

    return AnalysisResult(
        repository_root=str(root),
        analysis_mode="static",
        supported_frameworks=sorted(frameworks),
        files_scanned=files_scanned,
        prompts=_deduplicate(prompts),
        tools=_deduplicate(tools),
        models=_deduplicate(models),
        flows=_deduplicate(flows),
        guardrails=_deduplicate(guardrails),
        issues=issues,
    )


def _iter_python_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.py"):
        if ".git" not in path.parts and "__pycache__" not in path.parts:
            yield path


def _relative_file_path(path: Path) -> str:
    return path.as_posix()


def _iter_target_names(target: ast.AST) -> Iterable[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for item in target.elts:
            yield from _iter_target_names(item)


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append("{expr}")
        return "".join(parts)
    return None


def _callable_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _callable_name(node.func)
    return "unknown"


def _contains_hint(value: str, hints: Iterable[str]) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in hints)


def _looks_like_prompt_name(name: str) -> bool:
    return _contains_hint(name, PROMPT_NAME_HINTS)


def _extract_prompt_text_from_call(node: ast.Call) -> str:
    for keyword in node.keywords:
        if keyword.arg in {"content", "template"}:
            text = _literal_string(keyword.value)
            if text:
                return text
    if node.args:
        text = _literal_string(node.args[0])
        if text:
            return text
    return ""


def _summarize_call_arguments(node: ast.Call) -> dict[str, object]:
    positional = [_safe_unparse(argument) for argument in node.args]
    keywords = {
        keyword.arg if keyword.arg is not None else "kwargs": _safe_unparse(keyword.value)
        for keyword in node.keywords
    }
    return {"positional": positional, "keywords": keywords}


def _safe_unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return node.__class__.__name__


def _deduplicate(artifacts: list[Artifact]) -> list[Artifact]:
    unique: list[Artifact] = []
    seen: set[tuple[str, str, str, int]] = set()
    for artifact in artifacts:
        key = (artifact.kind, artifact.name, artifact.file_path, artifact.line)
        if key not in seen:
            seen.add(key)
            unique.append(artifact)
    return unique
