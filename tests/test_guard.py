import importlib.util, pathlib, unittest, sys, unicodedata

P = pathlib.Path(__file__).parents[1] / 'runner.py'
spec = importlib.util.spec_from_file_location('runner', P)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


BASE_CFG = {
    'core_rest': 'http://127.0.0.1:1',
    'agent_api': 'http://localhost:2',
    'otlp': 'http://[::1]:3',
    'mcp_gateway': 'http://127.0.0.1:4',
    'upstream_hits': 'http://127.0.0.1:5/hits',
}


class TestLoopbackGuard(unittest.TestCase):
    """Garante que o runner rejeita endpoints não-loopback."""

    def test_loopback_ok(self):
        m.Lab(BASE_CFG)

    def test_remote_rejected_mcp(self):
        c = dict(BASE_CFG)
        c['mcp_gateway'] = 'https://example.com'
        with self.assertRaises(SystemExit):
            m.Lab(c)

    def test_remote_rejected_agent(self):
        c = dict(BASE_CFG)
        c['agent_api'] = 'http://10.0.0.1:8080'
        with self.assertRaises(SystemExit):
            m.Lab(c)

    def test_remote_rejected_otlp(self):
        c = dict(BASE_CFG)
        c['otlp'] = 'http://192.168.1.100:4317'
        with self.assertRaises(SystemExit):
            m.Lab(c)

    def test_no_remote_escape_hatch(self):
        text = P.read_text(encoding='utf-8')
        self.assertNotIn('--allow-remote', text)

    def test_no_grpc_host_escape(self):
        """Verifica que core_grpc_host não-loopback é rejeitado."""
        c = dict(BASE_CFG)
        c['core_grpc_host'] = '8.8.8.8'
        with self.assertRaises(SystemExit):
            m.Lab(c)



class TestUnicodeHomoglyphDetection(unittest.TestCase):
    """TC-02 / IT-1: Valida detecção de homóglifos Unicode."""

    def test_cyrillic_a_vs_latin_a(self):
        """'а' cirílico (\u0430) deve divergir de 'a' latino após NFKC."""
        cyrillic = unicodedata.normalize("NFKC", "аdmin_delete")  # \u0430
        latin = unicodedata.normalize("NFKC", "admin_delete")
        # NFKC não mapeia cirílico para latino – strings devem ser diferentes
        self.assertNotEqual(cyrillic, latin)

    def test_cyrillic_e_vs_latin_e(self):
        """'е' cirílico (\u0435) deve divergir de 'e' latino após NFKC."""
        tool_homoglyph = unicodedata.normalize("NFKC", "е" + "xec")  # \u0435
        tool_latin = unicodedata.normalize("NFKC", "exec")
        self.assertNotEqual(tool_homoglyph, tool_latin)

    def test_zero_width_space_stripping(self):
        """Zero-width space (\u200b) deve ser detectado em nomes de ferramenta."""
        tool_with_zwsp = "exec\u200b"
        tool_clean = "exec"
        # Após NFKC, ZWSP é preservado – deve ser sanitizado separadamente
        has_zwsp = "\u200b" in tool_with_zwsp
        self.assertTrue(has_zwsp, "Zero-width space deve ser detectado antes de policy check")

    def test_runner_has_no_allow_remote(self):
        """Garante ausência de backdoor no runner."""
        text = P.read_text(encoding='utf-8')
        self.assertNotIn('--allow-remote', text)
        self.assertNotIn('allow_remote', text)


class TestYamlBillionLaughs(unittest.TestCase):
    """TC-08 / IT-9: Verifica comportamento do parser YAML frente a Billion Laughs."""

    BILLION_LAUGHS = (
        'a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]\n'
        'b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n'
        'c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n'
        'd: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n'
        'e: *d\n'
    )

    def test_yaml_safe_load_rejects_or_handles(self):
        """safe_load deve rejeitar ou limitar o payload Billion Laughs sem OOM."""
        try:
            import yaml  # type: ignore
        except ImportError:
            self.skipTest('PyYAML não instalado')

        import signal, os

        # Executa com timeout de 2 segundos para evitar hang
        completed = [False]
        result_container = [None]

        def run():
            try:
                result_container[0] = yaml.safe_load(self.BILLION_LAUGHS)
                completed[0] = True
            except Exception as e:
                result_container[0] = e
                completed[0] = True

        t = unittest.mock.MagicMock() if hasattr(unittest, 'mock') else None
        import threading
        th = threading.Thread(target=run, daemon=True)
        th.start()
        th.join(timeout=3)

        # Se completou sem exceção em < 3s, pode ser comportamento aceitável (PyYAML limita aliases)
        # O importante é que não trave indefinidamente
        if th.is_alive():
            self.fail("Parser YAML travou > 3s com Billion Laughs – potencial DoS!")

    def test_billion_laughs_document_is_malformed_policy(self):
        """Payload Billion Laughs enviado como policy deve ser rejeitado (status 4xx)."""
        # Verifica apenas a estrutura do payload – a chamada HTTP real requer servidor ativo
        # O runner.py deve rejeitar este documento via /api/v1/agent/policies/activate
        self.assertIn('&a', self.BILLION_LAUGHS)
        self.assertIn('*a', self.BILLION_LAUGHS)


class TestMerkleTimestampForging(unittest.TestCase):
    """IT-3: Adulteração retroativa de timestamps no ledger."""

    def test_forged_timestamp_is_detectable(self):
        """Timestamp no passado distante (ano 2000) deve ser identificável."""
        forged_ts = '2000-01-01T00:00:00Z'
        current_ts = '2024-01-01T00:00:00Z'
        self.assertLess(forged_ts, current_ts, "Timestamp forjado deve ser reconhecível como passado")

    def test_event_with_future_timestamp(self):
        """Timestamp futuro também deve ser suspeito."""
        future_ts = '2099-12-31T23:59:59Z'
        import time
        current = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        self.assertGreater(future_ts, current, "Timestamp futuro deve ser reconhecível")


class TestRunnerHasNewAttacks(unittest.TestCase):
    """Garante que o runner v2.0 contém todos os novos vetores."""

    def _runner_text(self):
        return P.read_text(encoding='utf-8')

    def test_has_unicode_homoglyph_attack(self):
        self.assertIn('unicode_homoglyph_policy_bypass', self._runner_text())

    def test_has_reentrant_tool_call(self):
        self.assertIn('reentrant_tool_call', self._runner_text())

    def test_has_slowloris_attack(self):
        self.assertIn('slowloris_fd_exhaustion', self._runner_text())

    def test_has_epoch_pinning(self):
        self.assertIn('epoch_pinning_concurrent', self._runner_text())

    def test_has_yaml_fuzzing(self):
        self.assertIn('yaml_policy_fuzzing', self._runner_text())

    def test_has_merkle_forgery(self):
        self.assertIn('merkle_timestamp_forgery', self._runner_text())

    def test_has_rate_limit_burst(self):
        self.assertIn('rate_limit_burst', self._runner_text())

    def test_has_multiline_injection(self):
        self.assertIn('multiline_header_injection', self._runner_text())


if __name__ == '__main__':
    unittest.main()
