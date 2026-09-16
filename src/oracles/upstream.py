"""
src/oracles/upstream.py
Oraculo de Efeitos Externos (Upstream Effect Oracle).
Garante que delta=None NUNCA seja tratado como zero.
"""
from __future__ import annotations
from typing import Optional, Tuple

class UpstreamEffectOracle:
    @staticmethod
    def evaluate(before: Optional[int], after: Optional[int], expected_delta: int = 0) -> Tuple[str, str]:
        """
        Avalia se a operacao respeitou a contagem exata de efeitos externos.
        Retorna (status, details).
        status: PASS, FAIL, ou INCONCLUSIVE (se contadores forem None).
        """
        if before is None or after is None:
            return (
                "INCONCLUSIVE",
                "Contador de upstream indisponivel ou stub inacessivel (delta=None). Impossivel comprovar efeito zero."
            )
        delta = after - before
        if delta < 0:
            return (
                "FAIL",
                f"Anomalia no upstream: contador regrediu de {before} para {after} (delta={delta})."
            )
        if delta == expected_delta:
            return (
                "PASS",
                f"Efeitos externos estritamente verificados: delta={delta} (esperado={expected_delta})."
            )
        return (
            "FAIL",
            f"VIOLACAO DE IDEMPOTENCIA/SEGURANCA: upstream produziu {delta} efeitos (esperado={expected_delta})."
        )
