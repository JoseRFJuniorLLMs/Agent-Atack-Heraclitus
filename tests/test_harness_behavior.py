"""
tests/test_harness_behavior.py
Testes comportamentais reais do harness (validação de oráculos, julgamento de falhas e testes negativos).
"""
import unittest
import asyncio
from pathlib import Path
from src.oracles.upstream import UpstreamEffectOracle
from src.oracles.durability import AcknowledgedLSNOracle
from src.oracles.merkle import MerkleOracle
from src.adapters.cli_invoker import run_cli_verify
import runner_v3 as v3


class TestHarnessBehavior(unittest.TestCase):
    def test_tc04_fails_when_workers_fail(self):
        """TC-04 deve retornar FAIL se qualquer worker falhar (elimina bug len(results) == tasks_count)."""
        # Porta 19999 fechada deliberadamente para forçar falha de todos os workers
        tester = v3.ConcurrencyStressTester("127.0.0.1", 19999)
        result = asyncio.run(tester.test_concurrent_read_write_monotonicity(tasks_count=5))
        self.assertEqual(result.status, "FAIL", "TC-04 retornou PASS mesmo com conexões falhando!")

    def test_tc05_skips_when_cli_missing(self):
        """TC-05 deve retornar SKIP quando o binário heraclitus-cli não existe, NUNCA PASS."""
        res = v3.StorageVerificationHook.run_verify("non_existent_cli_bin", "./data")
        self.assertEqual(res.status, "SKIP", f"TC-05 retornou {res.status} ao invés de SKIP para CLI inexistente")
        self.assertIn("nao encontrado", res.details.lower())

    def test_tc06_fails_when_server_offline(self):
        """TC-06 deve retornar FAIL se não conseguir abrir sockets nem probe."""
        attacker = v3.SlowlorisAttacker("127.0.0.1", 19999, num_sockets=5)
        result = asyncio.run(attacker.test_fd_exhaustion_slowloris())
        self.assertEqual(result.status, "FAIL", "Slowloris retornou PASS contra porta fechada!")

    def test_tc10_inconclusive_when_upstream_none(self):
        """TC-10 / UpstreamEffectOracle deve retornar INCONCLUSIVE quando delta=None."""
        status, detail = UpstreamEffectOracle.evaluate(None, None, expected_delta=0)
        self.assertEqual(status, "INCONCLUSIVE", "UpstreamEffectOracle aceitou None como válido!")

        status, detail = UpstreamEffectOracle.evaluate(10, None, expected_delta=0)
        self.assertEqual(status, "INCONCLUSIVE")

    def test_tc10_fails_when_upstream_delta_positive(self):
        """UpstreamEffectOracle deve retornar FAIL se houver qualquer vazamento de efeito externo."""
        status, detail = UpstreamEffectOracle.evaluate(before=10, after=11, expected_delta=0)
        self.assertEqual(status, "FAIL", "UpstreamEffectOracle permitiu vazamento de efeito externo!")
        self.assertIn("VIOLACAO", detail)

    def test_durability_oracle_detects_lost_lsn(self):
        """AcknowledgedLSNOracle deve falhar se um LSN confirmado sumir após restart."""
        oracle = AcknowledgedLSNOracle()
        oracle.record_ack(1, b"event_1")
        oracle.record_ack(2, b"event_2")
        oracle.record_ack(3, b"event_3")

        # Simula recuperação onde LSN 2 desapareceu
        recovered = [(1, b"event_1"), (3, b"event_3")]
        status, details = oracle.verify_after_restart(recovered)
        self.assertEqual(status, "FAIL", "Oráculo de durabilidade não detectou perda de LSN durável!")
        self.assertIn("perdidos", details)

    def test_durability_oracle_passes_when_all_persisted(self):
        """AcknowledgedLSNOracle deve passar quando todos os LSNs confirmados foram recuperados intactos."""
        oracle = AcknowledgedLSNOracle()
        oracle.record_ack(100, b"payload_100")
        oracle.record_ack(101, b"payload_101")

        recovered = [(100, b"payload_100"), (101, b"payload_101")]
        status, details = oracle.verify_after_restart(recovered)
        self.assertEqual(status, "PASS")
        self.assertIn("100% comprovada", details)

    def test_merkle_oracle_detects_tamper(self):
        """MerkleOracle deve provar que a alteração de bits em um bloco modifica o root."""
        leaves = [b"leaf_1", b"leaf_2", b"leaf_3", b"leaf_4"]
        orig_root = MerkleOracle.compute_root(leaves)

        tampered_leaves = [b"leaf_1", b"leaf_2_TAMPERED", b"leaf_3", b"leaf_4"]
        status, details = MerkleOracle.verify_tamper_detection(orig_root, tampered_leaves)
        self.assertEqual(status, "PASS")
        self.assertIn("Adulteracao detectada", details)


if __name__ == "__main__":
    unittest.main()
