"""
src/oracles/merkle.py
Oraculo de Integridade Merkle & Imutabilidade Temporal.
"""
from __future__ import annotations
import hashlib
from typing import List, Tuple

class MerkleOracle:
    @staticmethod
    def compute_root(leaves: List[bytes]) -> str:
        if not leaves:
            return hashlib.sha256(b"empty_merkle").hexdigest()
        current = [hashlib.sha256(leaf).digest() for leaf in leaves]
        while len(current) > 1:
            if len(current) % 2 != 0:
                current.append(current[-1])
            next_level = []
            for i in range(0, len(current), 2):
                h = hashlib.sha256(current[i] + current[i+1]).digest()
                next_level.append(h)
            current = next_level
        return current[0].hex()

    @staticmethod
    def verify_tamper_detection(orig_root: str, tampered_leaves: List[bytes]) -> Tuple[str, str]:
        new_root = MerkleOracle.compute_root(tampered_leaves)
        if new_root != orig_root:
            return (
                "PASS",
                f"Adulteracao detectada com sucesso. Root original={orig_root[:8]}... Root alterado={new_root[:8]}..."
            )
        return (
            "FAIL",
            "FALHA DE INTEGRIDADE: Merkle root permaneceu identico apos modificacao do payload!"
        )
