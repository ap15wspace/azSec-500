import json
import tempfile
import unittest
from pathlib import Path

from agentic_mapper.cli import main


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "sample_repo"


class CliTests(unittest.TestCase):
    def test_cli_writes_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "analysis.json"

            exit_code = main(
                ["analyze", str(FIXTURE_ROOT), "--output", str(output_path), "--pretty"]
            )

            self.assertEqual(exit_code, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["analysis_mode"], "static")
            self.assertEqual(payload["files_scanned"], 1)
