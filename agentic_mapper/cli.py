from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import analyze_repository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentic-mapper",
        description="Static reverse engineering for public agentic application repositories.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a local repository.")
    analyze_parser.add_argument("repository", type=Path, help="Absolute or relative path to the repository.")
    analyze_parser.add_argument("--output", type=Path, help="Optional output file path.")
    analyze_parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        result = analyze_repository(args.repository).to_dict()
        indent = 2 if args.pretty else None
        payload = json.dumps(result, indent=indent, sort_keys=True)
        if args.output:
            args.output.write_text(f"{payload}\n", encoding="utf-8")
        else:
            print(payload)
        return 0

    parser.error(f"Unsupported command: {args.command}")
    return 2
