import json
from pathlib import Path

from agentic_mapper.cli import main


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sample_repo"


def test_cli_writes_output_file(tmp_path: Path) -> None:
    output_path = tmp_path / "analysis.json"

    exit_code = main(["analyze", str(FIXTURE_ROOT), "--output", str(output_path), "--pretty"])

    assert exit_code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["analysis_mode"] == "static"
    assert payload["files_scanned"] == 1
