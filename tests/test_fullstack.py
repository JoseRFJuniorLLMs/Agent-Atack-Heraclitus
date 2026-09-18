import tempfile
import unittest
from pathlib import Path

from fullstack.process_probe import ProcessSnapshot, delta
from fullstack.protocol_attacks import _status_from_raw
from fullstack.storage_attacks import MARKER, candidates, require_disposable


class FullStackTests(unittest.TestCase):
    def test_process_delta(self):
        a = ProcessSnapshot(1, rss_kb=100, vm_kb=200, threads=3, fds=5); b = ProcessSnapshot(1, rss_kb=130, vm_kb=260, threads=4, fds=7)
        self.assertEqual(delta(a, b), {"rss_kb": 30, "vm_kb": 60, "threads": 1, "fds": 2})
    def test_raw_status(self):
        self.assertEqual(_status_from_raw(b"HTTP/1.1 403 Forbidden\r\n\r\n"), 403); self.assertIsNone(_status_from_raw(b"garbage"))
    def test_storage_requires_marker(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError): require_disposable(d)
            Path(d, MARKER).write_text("disposable"); self.assertEqual(require_disposable(d), Path(d).resolve())
    def test_storage_candidate_selection(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root / MARKER).write_text("disposable"); (root / "seg.hrkl").write_bytes(b"x" * 300); (root / "manifest.hrkm").write_bytes(b"y" * 100); (root / "notes.txt").write_text("ignore")
            self.assertEqual({p.name for p in candidates(root)}, {"seg.hrkl", "manifest.hrkm"})
    def test_production_like_roots_rejected(self):
        with self.assertRaises(ValueError): require_disposable("/mnt/data")


if __name__ == "__main__": unittest.main()
