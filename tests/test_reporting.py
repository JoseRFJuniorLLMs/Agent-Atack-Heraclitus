import importlib.util
import pathlib
import sys
import unittest

P = pathlib.Path(__file__).parents[1] / "runner.py"
spec = importlib.util.spec_from_file_location("runner_reporting", P)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class Reporting(unittest.TestCase):
    def test_markdown_contains_summary_and_vector(self):
        rows = [
            m.Result(
                attack_id="a1",
                vector="synthetic-vector",
                target="mcp:test",
                expected="blocked",
                result="blocked",
                passed=True,
                status=403,
                blocked=True,
                evidence_lsn=42,
            )
        ]
        text = m.markdown_report("Agent-Atack-Heraclitus", "demo", "smoke", rows)
        self.assertIn("PASS", text)
        self.assertIn("synthetic-vector", text)
        self.assertIn("42", text)


if __name__ == "__main__":
    unittest.main()
