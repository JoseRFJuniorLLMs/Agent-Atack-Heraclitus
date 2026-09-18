#!/usr/bin/env python3
"""
perpetual_runner.py — Execucao Continua 24/7 de Resiliencia e Testes Adversariais do HeraclitusDB

Executa ciclicamente o harness SuperRunnerV4 em modo perpetuo (loop 24/7):
- Monitora tempo de resposta, invariantes de durabilidade e integridade fisica.
- Mantem metricas acumuladas em reports/live_status.json.
- Realiza rotacao e expurgo automatico de relatorios antigos (evita estouro de disco).
- Suporta sinais SIGINT/SIGTERM para finalizacao graciosa.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from runner_v4 import SuperRunnerV4


def is_phase_passed(phase_data: Any) -> bool:
    if isinstance(phase_data, str):
        return phase_data in ("EXECUTED", "PASS", "OK")
    if isinstance(phase_data, dict):
        if phase_data.get("status") in ("FAIL", "ERROR"):
            return False
        if phase_data.get("resilient") is False:
            return False
        if phase_data.get("split_brain_detected") is True:
            return False
        doc = phase_data.get("doctor_verify")
        if isinstance(doc, dict) and doc.get("status") not in ("PASS", "SKIP", "OK"):
            return False
        return True
    return bool(phase_data)


class PerpetualChaosLab:
    def __init__(
        self,
        profile: str = "full",
        delay_seconds: float = 3.0,
        max_retained_reports: int = 50,
        reports_dir: str = "reports"
    ):
        self.profile = profile
        self.delay_seconds = delay_seconds
        self.max_retained_reports = max_retained_reports
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.status_file = self.reports_dir / "live_status.json"
        self.shutdown_requested = False

        self.stats = {
            "service": "HeraclitusDB-Adversarial-Lab-24-7",
            "profile": self.profile,
            "running": True,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "total_cycles": 0,
            "total_pass": 0,
            "total_fail": 0,
            "consecutive_failures": 0,
            "last_cycle": 0,
            "last_cycle_timestamp": None,
            "last_cycle_duration_sec": 0.0,
            "last_status": "STARTING",
            "last_error": None,
            "average_cycle_duration_sec": 0.0
        }
        self._load_previous_stats()

    def _load_previous_stats(self) -> None:
        if self.status_file.exists():
            try:
                data = json.loads(self.status_file.read_text(encoding="utf-8"))
                self.stats["total_cycles"] = data.get("total_cycles", 0)
                self.stats["total_pass"] = data.get("total_pass", 0)
                self.stats["total_fail"] = data.get("total_fail", 0)
                self.stats["last_cycle"] = data.get("last_cycle", 0)
            except Exception:
                pass

    def _save_stats(self) -> None:
        try:
            self.stats["updated_at"] = datetime.now(timezone.utc).isoformat()
            tmp_file = self.status_file.with_suffix(".tmp")
            tmp_file.write_text(json.dumps(self.stats, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp_file.replace(self.status_file)
        except Exception as e:
            print(f"[WARN] Falha ao gravar status: {e}", file=sys.stderr)

    def prune_old_reports(self) -> None:
        """Remove relatorios antigos alem de max_retained_reports para preservar disco."""
        try:
            for pattern in ("audit_chaos_report_*.json", "audit_chaos_report_*.md", "teste_heraclitus_v3_*.json", "teste_heraclitus_v3_*.md"):
                files = sorted(self.reports_dir.glob(pattern), key=os.path.getmtime)
                if len(files) > self.max_retained_reports:
                    to_remove = files[:-self.max_retained_reports]
                    for f in to_remove:
                        try:
                            f.unlink(missing_ok=True)
                        except OSError:
                            pass
        except Exception as e:
            print(f"[WARN] Erro no expurgo de relatorios: {e}", file=sys.stderr)

    def request_shutdown(self, signum, frame):
        sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        print(f"\n[!] Sinal recebido ({sig_name}). Finalizando com seguranca...")
        self.shutdown_requested = True
        self.stats["running"] = False
        self.stats["last_status"] = "STOPPED"
        self._save_stats()

    async def run_forever(self) -> None:
        signal.signal(signal.SIGINT, self.request_shutdown)
        signal.signal(signal.SIGTERM, self.request_shutdown)

        print("=" * 70)
        print("   HERACLITUSDB - LABORATORIO ADVERSARIAL PERPETUO (24/7)")
        print(f"   Perfil: {self.profile.upper()} | Delay entre ciclos: {self.delay_seconds}s")
        print(f"   Relatorios em: {self.reports_dir.resolve()}")
        print("=" * 70)

        total_duration = 0.0
        while not self.shutdown_requested:
            self.stats["total_cycles"] += 1
            cycle = self.stats["total_cycles"]
            self.stats["last_cycle"] = cycle
            self.stats["last_cycle_timestamp"] = datetime.now(timezone.utc).isoformat()
            self.stats["running"] = True

            print(f"\n>>> [CICLO #{cycle:06d}] Iniciando em {self.stats['last_cycle_timestamp']}...")
            cycle_start = time.perf_counter()

            try:
                runner = SuperRunnerV4(profile_name=self.profile)
                res = await runner.execute_all()
                duration = time.perf_counter() - cycle_start
                total_duration += duration
                self.stats["last_cycle_duration_sec"] = round(duration, 2)
                self.stats["average_cycle_duration_sec"] = round(total_duration / cycle, 2)

                phases = res.get("phases", {})
                all_ok = all(is_phase_passed(v) for v in phases.values()) if phases else True

                if all_ok:
                    self.stats["total_pass"] += 1
                    self.stats["consecutive_failures"] = 0
                    self.stats["last_status"] = "PASS"
                    self.stats["last_error"] = None
                    print(f"<<< [CICLO #{cycle:06d}] CONCLUIDO: PASS ({duration:.2f}s) | Total PASS={self.stats['total_pass']} FAIL={self.stats['total_fail']}")
                else:
                    self.stats["total_fail"] += 1
                    self.stats["consecutive_failures"] += 1
                    self.stats["last_status"] = "FAIL"
                    print(f"<<< [CICLO #{cycle:06d}] CONCLUIDO: FAIL ({duration:.2f}s) | Phases: {phases}")

            except Exception as e:
                duration = time.perf_counter() - cycle_start
                self.stats["total_fail"] += 1
                self.stats["consecutive_failures"] += 1
                self.stats["last_status"] = "ERROR"
                self.stats["last_error"] = f"{type(e).__name__}: {str(e)}"
                print(f"[!] [CICLO #{cycle:06d}] ERRO INESPERADO ({duration:.2f}s): {e}", file=sys.stderr)

            self._save_stats()
            self.prune_old_reports()

            if self.shutdown_requested:
                break

            print(f"[*] Pausa de {self.delay_seconds}s antes do proximo ciclo...")
            await asyncio.sleep(self.delay_seconds)

        print("[OK] Loop perpetuo encerrado.")


def main():
    parser = argparse.ArgumentParser(description="HeraclitusDB Perpetual Adversarial Runner (24/7)")
    parser.add_argument("--profile", choices=["smoke", "full", "destructive"], default="full", help="Perfil do runner (default: full)")
    parser.add_argument("--delay", type=float, default=3.0, help="Intervalo em segundos entre ciclos (default: 3.0)")
    parser.add_argument("--max-reports", type=int, default=50, help="Maximo de relatorios retidos no disco (default: 50)")
    parser.add_argument("--reports-dir", default="reports", help="Diretorio dos relatorios")
    args = parser.parse_args()

    lab = PerpetualChaosLab(
        profile=args.profile,
        delay_seconds=args.delay,
        max_retained_reports=args.max_reports,
        reports_dir=args.reports_dir
    )
    asyncio.run(lab.run_forever())


if __name__ == "__main__":
    main()
