"""
src/oracles/durability.py
Oraculo de Durabilidade (Acknowledged LSN Oracle).
Registra cada escrita reconhecida como duravel (ACKED_LSN).
Apos crash/SIGKILL/restart, comprova que nenhum LSN reconhecido sumiu silenciosamente.
"""
from __future__ import annotations
import hashlib
from typing import Dict, List, Optional, Tuple

class AcknowledgedLSNOracle:
    def __init__(self):
        self._acked: Dict[int, str] = {}

    def record_ack(self, lsn: int, payload: bytes | str) -> None:
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()
        self._acked[lsn] = digest

    @property
    def total_acked(self) -> int:
        return len(self._acked)

    def verify_after_restart(self, recovered_events: List[Tuple[int, bytes | str]]) -> Tuple[str, str]:
        """
        Compara o conjunto de eventos recuperados do storage contra a tabela ACKED_LSN.
        SPEC-0049: Jamais deve existir 'acknowledged as durable + silently absent after restart'.
        """
        recovered_map: Dict[int, str] = {}
        for lsn, payload in recovered_events:
            if isinstance(payload, str):
                payload = payload.encode("utf-8")
            recovered_map[lsn] = hashlib.sha256(payload).hexdigest()

        missing_lsns: List[int] = []
        corrupted_lsns: List[int] = []

        for acked_lsn, expected_hash in self._acked.items():
            if acked_lsn not in recovered_map:
                missing_lsns.append(acked_lsn)
            elif recovered_map[acked_lsn] != expected_hash:
                corrupted_lsns.append(acked_lsn)

        if not missing_lsns and not corrupted_lsns:
            return (
                "PASS",
                f"Durabilidade 100% comprovada: todos os {len(self._acked)} LSNs persistiram intactos."
            )

        details = []
        if missing_lsns:
            details.append(f"LSNs reconhecidos perdidos: {missing_lsns[:10]} (total {len(missing_lsns)})")
        if corrupted_lsns:
            details.append(f"LSNs com hash divergente: {corrupted_lsns[:10]} (total {len(corrupted_lsns)})")

        return ("FAIL", "; ".join(details))
