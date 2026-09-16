import argparse
import importlib.util
import pathlib
import sys
import unittest

P = pathlib.Path(__file__).parents[1] / "runner.py"
spec = importlib.util.spec_from_file_location("runner", P)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class Guard(unittest.TestCase):
    def base(self):
        return {
            "core_rest": "http://127.0.0.1:1",
            "agent_api": "http://localhost:2",
            "otlp": "http://[::1]:3",
            "mcp_gateway": "http://127.0.0.1:4",
            "upstream_hits": "http://127.0.0.1:5/hits",
        }

    def test_loopback_ok(self):
        m.Lab(self.base(), "smoke")

    def test_remote_rejected(self):
        c = self.base()
        c["mcp_gateway"] = "https://example.com"
        with self.assertRaises(SystemExit):
            m.Lab(c, "smoke")

    def test_grpc_remote_rejected(self):
        c = self.base()
        c["core_grpc_host"] = "8.8.8.8"
        with self.assertRaises(SystemExit):
            m.Lab(c, "smoke")

    def test_no_remote_escape_hatch(self):
        text = P.read_text(encoding="utf-8")
        self.assertNotIn("--allow-remote", text)
        self.assertNotIn("allow_remote", text)

    def test_caps_agents(self):
        c = self.base()
        c["agents"] = m.MAX_AGENTS + 1
        with self.assertRaises(SystemExit):
            m.Lab(c, "massive")

    def test_caps_concurrency(self):
        c = self.base()
        c["concurrency"] = m.MAX_CONCURRENCY + 1
        with self.assertRaises(SystemExit):
            m.Lab(c, "massive")

    def test_caps_iterations(self):
        c = self.base()
        c["iterations"] = m.MAX_ITERATIONS + 1
        with self.assertRaises(SystemExit):
            m.Lab(c, "massive")

    def test_profiles_exist(self):
        self.assertEqual({"smoke", "full", "massive"}, set(m.PROFILES))
        self.assertIn("multi_agent_swarm", m.PROFILES["massive"]["suites"])

    def test_personas_have_adversarial_mix(self):
        self.assertIn("malicious", m.PERSONAS)
        self.assertIn("replay-bot", m.PERSONAS)
        self.assertIn("benign-control", m.PERSONAS)


if __name__ == "__main__":
    unittest.main()
