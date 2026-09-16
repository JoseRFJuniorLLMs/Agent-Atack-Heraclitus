import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).parents[1]

# runner_v3 importa `runner` pelo nome normal; carregamos o v2 primeiro.
base_spec = importlib.util.spec_from_file_location("runner", ROOT / "runner.py")
base = importlib.util.module_from_spec(base_spec)
sys.modules[base_spec.name] = base
base_spec.loader.exec_module(base)

v3_spec = importlib.util.spec_from_file_location("runner_v3", ROOT / "runner_v3.py")
v3 = importlib.util.module_from_spec(v3_spec)
sys.modules[v3_spec.name] = v3
v3_spec.loader.exec_module(v3)


class V3Guard(unittest.TestCase):
    def cfg(self):
        return {
            "core_rest": "http://127.0.0.1:17475",
            "core_grpc_host": "127.0.0.1",
            "core_grpc_port": 17474,
            "agent_api": "http://localhost:18080",
            "otlp": "http://[::1]:14318",
            "mcp_gateway": "http://127.0.0.1:18787",
            "upstream_hits": "http://127.0.0.1:19000/hits",
        }

    def test_v3_stays_loopback_only(self):
        v3.AdvancedLab(self.cfg(), "smoke")
        bad = self.cfg()
        bad["upstream_hits"] = "https://example.com/stats"
        with self.assertRaises(SystemExit):
            v3.AdvancedLab(bad, "smoke")

    def test_no_remote_escape_hatch(self):
        text = (ROOT / "runner_v3.py").read_text(encoding="utf-8")
        self.assertNotIn("--allow-remote", text)
        self.assertNotIn("allow_remote", text)

    def test_recursive_audit_vectors_are_enabled(self):
        massive = set(v3.EXTRA_SUITES["massive"])
        self.assertIn("mcp_header_body_differentials", massive)
        self.assertIn("header_forwarding_boundaries", massive)
        self.assertIn("gateway_auth_boundary", massive)
        self.assertIn("protocol_data_methods_policy", massive)
        self.assertIn("upstream_response_limit", massive)

    def test_v3_keeps_v2_caps(self):
        c = self.cfg()
        c["agents"] = base.MAX_AGENTS + 1
        with self.assertRaises(SystemExit):
            v3.AdvancedLab(c, "massive")

    def test_stub_never_records_authorization_value(self):
        text = (ROOT / "stub_upstream.py").read_text(encoding="utf-8")
        self.assertIn('"authorization": headers.get("Authorization") is not None', text)
        self.assertNotIn('"authorization": headers.get("Authorization"),', text)
        self.assertNotIn("dict(self.headers)", text)

    def test_safe_exec_markers_only(self):
        text = (ROOT / "runner_v3.py").read_text(encoding="utf-8")
        self.assertIn("echo SAFE_MARKER", text)
        self.assertNotIn("rm -rf", text)
        self.assertNotIn("subprocess", text)
        self.assertNotIn("os.system", text)


if __name__ == "__main__":
    unittest.main()
