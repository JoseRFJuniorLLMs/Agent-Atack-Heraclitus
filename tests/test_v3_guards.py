import tempfile,unittest
from pathlib import Path
from attacks.common import LabContext
from attacks.storage import MARKER,require_disposable
class GuardTests(unittest.TestCase):
 def config(self):return {"core_rest":"http://127.0.0.1:17475","agent_api":"http://localhost:18080","otlp":"http://[::1]:14318","mcp_gateway":"http://127.0.0.1:18787","upstream_hits":"http://127.0.0.1:19000/hits"}
 def test_loopback_allowed(self):LabContext(self.config())
 def test_remote_rejected(self):
  c=self.config();c["mcp_gateway"]="https://example.com"
  with self.assertRaises(SystemExit):LabContext(c)
 def test_disposable_requires_marker(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError):require_disposable(d)
   Path(d,MARKER).write_text("ok");self.assertEqual(require_disposable(d),Path(d).resolve())
 def test_dangerous_root_rejected(self):
  with self.assertRaises(ValueError):require_disposable("/mnt/data")
if __name__=="__main__":unittest.main()
