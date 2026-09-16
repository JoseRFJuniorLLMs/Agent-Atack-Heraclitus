import json,tempfile,unittest
from pathlib import Path
from attacks.common import AttackResult
from reporting import summary,write_json,write_junit,write_markdown
class ReportingTests(unittest.TestCase):
 def rows(self):return [AttackResult("a1","deny","gateway","mcp","403","403",True,upstream_delta=0,native_evidence=True),AttackResult("a2","bad","protocol","mcp","reject","forwarded",False,upstream_delta=1,native_evidence=False)]
 def test_summary(self):self.assertEqual(summary(self.rows()),{"total":2,"passed":1,"failed":1,"native_observability_missing":1})
 def test_all_report_formats(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d);write_json(r/"r.json","c",self.rows());write_markdown(r/"r.md","c",self.rows());write_junit(r/"r.xml","c",self.rows());self.assertEqual(json.loads((r/"r.json").read_text())["summary"]["failed"],1);self.assertIn("Native evidence",(r/"r.md").read_text());self.assertIn("testsuite",(r/"r.xml").read_text())
if __name__=="__main__":unittest.main()
