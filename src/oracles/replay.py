"""
src/oracles/replay.py
Oraculo de Equivalencia de Reconstrucao (Differential Replay).
"""
from __future__ import annotations
from typing import Dict, Any, Tuple

class ReplayEquivalenceOracle:
    @staticmethod
    def verify_equivalence(online_state: Dict[str, Any], replayed_state: Dict[str, Any]) -> Tuple[str, str]:
        if online_state == replayed_state:
            return ("PASS", "Estado reconstruido a partir de LSN 0 identico ao estado online.")
        diff_keys = [k for k in online_state if online_state.get(k) != replayed_state.get(k)]
        return ("FAIL", f"Divergencia pos-replay nas chaves: {diff_keys[:5]}")
