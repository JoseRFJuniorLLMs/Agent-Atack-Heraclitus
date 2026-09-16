"""
test_reporting.py — Validação da geração de relatórios de conformidade e detecção.

Testa:
  - Estrutura e campos obrigatórios do JSON de relatório
  - Geração de Markdown com tabela de resultados
  - Consistência entre summary e lista de casos
  - Detecção de FAIL propagada corretamente para overall_status
  - Campos de telemetria (delta_fds, delta_rss_mb)
  - Auditabilidade: relatório contém evidence_lsn quando disponível
"""
import json
import time
import unittest
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional
import tempfile
import os


@dataclass
class MockResult:
    attack_id: str
    vector: str
    target: str
    expected: str
    result: str
    passed: bool
    status: Optional[int] = None
    reason_code: Optional[str] = None
    blocked: Optional[bool] = None
    upstream_delta: Optional[int] = None
    detail: str = ''
    duration_ms: float = 0.0
    evidence_lsn: Optional[int] = None


def build_report(results: List[MockResult], delta_fds: int = 0, delta_rss: float = 0.0) -> dict:
    """Constrói estrutura de relatório compatível com o runner."""
    overall_pass = all(r.passed for r in results) and delta_fds <= 5
    return {
        'product': 'Agent-Atack-Heraclitus',
        'version': '2.0.0',
        'campaign': f'test-{int(time.time())}',
        'generated_at': int(time.time()),
        'overall_status': 'PASS' if overall_pass else 'FAIL',
        'metrics': {
            'delta_open_fds': delta_fds,
            'delta_rss_mb': delta_rss,
        },
        'results': [asdict(r) for r in results],
        'summary': {
            'total': len(results),
            'passed': sum(r.passed for r in results),
            'failed': sum(not r.passed for r in results),
        }
    }


class TestReportStructure(unittest.TestCase):
    """Valida campos obrigatórios no relatório JSON."""

    def _make_results(self, n_pass=3, n_fail=0):
        results = []
        for i in range(n_pass):
            results.append(MockResult(f'atk-{i}', f'vector-{i}', 'target', 'PASS', 'PASS',
                                      True, 200, None, True, 0, 'ok', 10.0 + i, i + 1))
        for i in range(n_fail):
            results.append(MockResult(f'atk-fail-{i}', f'vector-fail-{i}', 'target', 'BLOCK',
                                      'PASS', False, 200, None, False, 1, 'leaked', 5.0, None))
        return results

    def test_required_keys_present(self):
        r = build_report(self._make_results())
        for key in ['product', 'version', 'campaign', 'generated_at', 'overall_status',
                    'metrics', 'results', 'summary']:
            self.assertIn(key, r, f"Campo obrigatório ausente: {key}")

    def test_summary_totals_correct(self):
        results = self._make_results(n_pass=5, n_fail=2)
        r = build_report(results)
        self.assertEqual(r['summary']['total'], 7)
        self.assertEqual(r['summary']['passed'], 5)
        self.assertEqual(r['summary']['failed'], 2)

    def test_overall_pass_all_passed(self):
        r = build_report(self._make_results(n_pass=3, n_fail=0))
        self.assertEqual(r['overall_status'], 'PASS')

    def test_overall_fail_when_any_failed(self):
        r = build_report(self._make_results(n_pass=3, n_fail=1))
        self.assertEqual(r['overall_status'], 'FAIL')

    def test_overall_fail_on_fd_leak(self):
        """delta_fds > 5 deve forçar overall_status = FAIL."""
        r = build_report(self._make_results(n_pass=3), delta_fds=10)
        self.assertEqual(r['overall_status'], 'FAIL')

    def test_metrics_keys_present(self):
        r = build_report(self._make_results())
        self.assertIn('delta_open_fds', r['metrics'])
        self.assertIn('delta_rss_mb', r['metrics'])

    def test_results_contain_required_fields(self):
        results = self._make_results(n_pass=1)
        r = build_report(results)
        entry = r['results'][0]
        for field in ['attack_id', 'vector', 'target', 'expected', 'result', 'passed',
                      'status', 'blocked', 'detail', 'duration_ms']:
            self.assertIn(field, entry, f"Campo de resultado ausente: {field}")

    def test_evidence_lsn_preserved(self):
        """LSN de evidência deve ser preservado no relatório."""
        results = [MockResult('atk-1', 'mcp-deny', 'mcp:exec', '403', '403',
                               True, 403, 'POLICY_DENY', True, 0, 'blocked', 12.5, evidence_lsn=42)]
        r = build_report(results)
        self.assertEqual(r['results'][0]['evidence_lsn'], 42)


class TestReportJson(unittest.TestCase):
    """Valida serialização e desserialização do relatório."""

    def test_json_round_trip(self):
        """Relatório deve ser serializável e desserializável sem perda."""
        results = [
            MockResult('atk-1', 'otlp-malformed', 'otlp:/v1/traces', '400', '400',
                       True, 400, None, True, None, 'malformed rejeitado', 15.2, 7),
            MockResult('atk-2', 'mcp-policy-deny', 'mcp:exec', '403', '403',
                       True, 403, 'POLICY_DENY', True, 0, 'bloqueado', 8.1, 8),
        ]
        report = build_report(results)
        serialized = json.dumps(report, indent=2, ensure_ascii=False)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized['summary']['total'], 2)
        self.assertEqual(deserialized['summary']['passed'], 2)

    def test_report_written_to_file(self):
        """Relatório deve ser gravável em disco e legível."""
        results = [MockResult('atk-1', 'test', 'target', 'PASS', 'PASS', True, 200, None, True, 0)]
        report = build_report(results)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / 'test_report.json'
            path.write_text(json.dumps(report, indent=2))
            loaded = json.loads(path.read_text())
            self.assertEqual(loaded['overall_status'], 'PASS')
            self.assertTrue(path.exists())

    def test_report_non_ascii_detail_preserved(self):
        """Campos com caracteres não-ASCII devem ser preservados (ensure_ascii=False)."""
        results = [MockResult('atk-1', 'unicode', 'policy', 'BLOCK', 'BLOCK',
                              True, 403, None, True, 0,
                              'Homóglifo cirílico detectado: а (\\u0430)', 5.0)]
        report = build_report(results)
        serialized = json.dumps(report, ensure_ascii=False)
        self.assertIn('Homóglifo', serialized)
        self.assertIn('cirílico', serialized)


class TestMarkdownGeneration(unittest.TestCase):
    """Valida geração do relatório Markdown."""

    def _make_markdown(self, results):
        """Reproduz a lógica de generate_markdown do TesteHeraclitusOrchestrator."""
        lines = [
            "# Relatório de Execução — TesteHeraclitusDB",
            "",
            "| ID | Descrição | Status | Latência | Detalhes |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for r in results:
            icon = "✅" if r.passed else "❌"
            status = "PASS" if r.passed else "FAIL"
            lines.append(f"| `{r.attack_id}` | {r.vector} | {icon} **`{status}`** | {r.duration_ms} ms | {r.detail} |")
        return "\n".join(lines)

    def test_markdown_contains_pass_icon(self):
        results = [MockResult('t1', 'mcp-deny', 'mcp', 'PASS', 'PASS', True, 403, None, True, 0)]
        md = self._make_markdown(results)
        self.assertIn('✅', md)

    def test_markdown_contains_fail_icon(self):
        results = [MockResult('t1', 'mcp-deny', 'mcp', 'PASS', 'FAIL', False, 200, None, False, 1)]
        md = self._make_markdown(results)
        self.assertIn('❌', md)

    def test_markdown_has_table_header(self):
        results = []
        md = self._make_markdown(results)
        self.assertIn('| ID |', md)
        self.assertIn('| Descrição |', md)
        self.assertIn('| Status |', md)

    def test_markdown_attack_ids_present(self):
        results = [
            MockResult('TC-01', 'idle-timeout', 'tcp', 'PASS', 'PASS', True, None, None, None, None),
            MockResult('TC-06', 'slowloris', 'tcp:mcp', 'PASS', 'PASS', True, None, None, None, None),
        ]
        md = self._make_markdown(results)
        self.assertIn('TC-01', md)
        self.assertIn('TC-06', md)


class TestReportCampaignConsistency(unittest.TestCase):
    """Valida consistência de campaign_id em todos os eventos."""

    def test_campaign_id_consistent(self):
        """Todos os resultados devem referenciar o mesmo campaign_id."""
        campaign = f'sandbox-{int(time.time())}'
        results = [
            MockResult(f'{campaign}-atk-{i}', f'vector-{i}', 'target', 'PASS', 'PASS', True)
            for i in range(5)
        ]
        # Verifica que attack_ids derivam do mesmo campaign prefix
        for r in results:
            self.assertTrue(r.attack_id.startswith(campaign))

    def test_sequential_ordering(self):
        """Resultados devem manter ordem de execução."""
        results = [MockResult(f'atk-{i}', f'v{i}', 't', 'P', 'P', True, duration_ms=float(i))
                   for i in range(10)]
        report = build_report(results)
        for idx, entry in enumerate(report['results']):
            self.assertEqual(entry['duration_ms'], float(idx))


if __name__ == '__main__':
    unittest.main()
