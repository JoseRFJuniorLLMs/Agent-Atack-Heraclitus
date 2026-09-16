"""
test_v3.py — Guardrails do harness runner_v3 (TesteHeraclitusOrchestrator).

Verifica:
  - Loopback-only enforcement em TesteHeraclitusOrchestrator
  - Ausência de --allow-remote e allow_remote em runner_v3.py
  - Ausência de chamadas de shell perigosas (os.system, subprocess.call)
  - Presença do marcador seguro SAFE_MARKER
  - Presença de vetores adversariais críticos no runner_v3.py
  - Ausência de vazamento do valor de Authorization no stub
"""
import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).parents[1]

# Carrega runner.py (runner_v3 depende dele pelo nome 'runner')
base_spec = importlib.util.spec_from_file_location("runner", ROOT / "runner.py")
base = importlib.util.module_from_spec(base_spec)
sys.modules[base_spec.name] = base
base_spec.loader.exec_module(base)

# Carrega runner_v3.py
v3_spec = importlib.util.spec_from_file_location("runner_v3", ROOT / "runner_v3.py")
v3 = importlib.util.module_from_spec(v3_spec)
sys.modules[v3_spec.name] = v3
v3_spec.loader.exec_module(v3)


GOOD_CFG = {
    "core_rest": "http://127.0.0.1:17475",
    "core_grpc_host": "127.0.0.1",
    "core_grpc_port": 17474,
    "agent_api": "http://localhost:18080",
    "otlp": "http://[::1]:14318",
    "mcp_gateway": "http://127.0.0.1:18787",
    "upstream_hits": "http://127.0.0.1:19000/hits",
}


class V3Guard(unittest.TestCase):
    """Guardrails de segurança do harness v3."""

    # ------------------------------------------------------------------ #
    # Módulos e classes exportados                                          #
    # ------------------------------------------------------------------ #

    def test_orchestrator_class_exported(self):
        """runner_v3 deve exportar TesteHeraclitusOrchestrator."""
        self.assertTrue(hasattr(v3, "TesteHeraclitusOrchestrator"))

    def test_orchestrator_accepts_loopback_config(self):
        """TesteHeraclitusOrchestrator deve aceitar config 100% loopback."""
        # Apenas instancia — não executa campanha
        v3.TesteHeraclitusOrchestrator(GOOD_CFG)

    def test_orchestrator_rejects_remote_upstream_hits(self):
        bad = dict(GOOD_CFG)
        bad["upstream_hits"] = "https://example.com/stats"
        with self.assertRaises(SystemExit):
            v3.TesteHeraclitusOrchestrator(bad)

    def test_orchestrator_rejects_remote_mcp_gateway(self):
        bad = dict(GOOD_CFG)
        bad["mcp_gateway"] = "http://10.10.10.10:18787"
        with self.assertRaises(SystemExit):
            v3.TesteHeraclitusOrchestrator(bad)

    def test_orchestrator_rejects_remote_agent_api(self):
        bad = dict(GOOD_CFG)
        bad["agent_api"] = "http://192.168.0.1:18080"
        with self.assertRaises(SystemExit):
            v3.TesteHeraclitusOrchestrator(bad)

    # ------------------------------------------------------------------ #
    # Ausência de backdoors                                                 #
    # ------------------------------------------------------------------ #

    def test_no_allow_remote_in_v3(self):
        text = (ROOT / "runner_v3.py").read_text(encoding="utf-8")
        self.assertNotIn("--allow-remote", text)
        self.assertNotIn("allow_remote", text)

    def test_no_allow_remote_in_runner(self):
        text = (ROOT / "runner.py").read_text(encoding="utf-8")
        self.assertNotIn("--allow-remote", text)
        self.assertNotIn("allow_remote", text)

    # ------------------------------------------------------------------ #
    # Ausência de chamadas de shell perigosas                               #
    # ------------------------------------------------------------------ #

    def test_no_dangerous_shell_calls_in_v3(self):
        """runner_v3 não deve conter rm -rf, os.system ou subprocess.call."""
        text = (ROOT / "runner_v3.py").read_text(encoding="utf-8")
        self.assertNotIn("rm -rf", text)
        self.assertNotIn("os.system(", text)
        self.assertNotIn("subprocess.call(", text)
        self.assertNotIn("subprocess.Popen(", text)
        self.assertNotIn("shell=True", text)

    def test_no_dangerous_calls_in_stub(self):
        """stub_upstream não deve conter chamadas de shell."""
        text = (ROOT / "stub_upstream.py").read_text(encoding="utf-8")
        self.assertNotIn("os.system(", text)
        self.assertNotIn("os.popen(", text)
        self.assertNotIn("import subprocess", text)
        self.assertNotIn("subprocess.", text)

    # ------------------------------------------------------------------ #
    # Marcadores seguros                                                    #
    # ------------------------------------------------------------------ #

    def test_safe_marker_in_v3(self):
        """runner_v3 deve usar SAFE_MARKER para simular exec sem execução real."""
        text = (ROOT / "runner_v3.py").read_text(encoding="utf-8")
        self.assertIn("SAFE_MARKER", text)

    # ------------------------------------------------------------------ #
    # Stub: não vaza valor de Authorization                                 #
    # ------------------------------------------------------------------ #

    def test_stub_does_not_log_authorization_value(self):
        """O stub nunca deve registrar o valor do header Authorization."""
        text = (ROOT / "stub_upstream.py").read_text(encoding="utf-8")
        self.assertNotIn("dict(self.headers)", text)
        self.assertNotIn("os.system(", text)

    # ------------------------------------------------------------------ #
    # Presença de classes/vetores críticos no runner_v3                    #
    # ------------------------------------------------------------------ #

    def test_has_slowloris_attacker_class(self):
        self.assertTrue(hasattr(v3, "SlowlorisAttacker"))

    def test_has_epoch_pinning_class(self):
        self.assertTrue(hasattr(v3, "EpochPinningAttacker"))

    def test_has_manifest_poisoning_class(self):
        self.assertTrue(hasattr(v3, "ManifestPoisoningAttacker"))

    def test_has_yaml_poison_class(self):
        self.assertTrue(hasattr(v3, "YamlPoisonAttacker"))

    def test_has_tool_call_reentrancy_class(self):
        self.assertTrue(hasattr(v3, "ToolCallReentracyAttacker"))

    def test_has_concurrency_stress_class(self):
        self.assertTrue(hasattr(v3, "ConcurrencyStressTester"))

    def test_has_protocol_resilience_class(self):
        self.assertTrue(hasattr(v3, "ProtocolResilienceTester"))

    # ------------------------------------------------------------------ #
    # Caps herdados do runner.py                                            #
    # ------------------------------------------------------------------ #

    def test_runner_exports_lab_class(self):
        """runner.py deve exportar Lab como classe de configuração."""
        self.assertTrue(hasattr(base, "Lab"), "runner.py deve exportar Lab")

    def test_runner_exports_loopback_set(self):
        """runner.py deve exportar LOOPBACK como conjunto de hosts válidos."""
        self.assertTrue(hasattr(base, "LOOPBACK"), "runner.py deve exportar LOOPBACK")

    def test_v3_exports_main_callable(self):
        """runner_v3 deve exportar main() para uso em CLI."""
        self.assertTrue(hasattr(v3, "main") and callable(v3.main))


if __name__ == "__main__":
    unittest.main()
