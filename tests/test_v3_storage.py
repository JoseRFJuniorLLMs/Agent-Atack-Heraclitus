import tempfile,unittest
from pathlib import Path
from attacks.storage import MARKER,_files,require_disposable
class StorageTests(unittest.TestCase):
 def test_candidates_and_marker(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d);(r/MARKER).write_text("ok");(r/"segment.hrkl").write_bytes(b"x"*300);(r/"notes.txt").write_text("no");self.assertEqual(require_disposable(r),r.resolve());self.assertEqual([p.name for p in _files(r)],["segment.hrkl"])
if __name__=="__main__":unittest.main()
