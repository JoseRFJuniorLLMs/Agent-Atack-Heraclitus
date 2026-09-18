#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def main():
    root = Path(__file__).resolve().parent
    p = root / "reports" / "live_status.json"
    if not p.exists():
        print(f"Nenhum dado de status encontrado ainda em {p}.")
        sys.exit(0)
    data = json.loads(p.read_text(encoding="utf-8"))
    print("=" * 60)
    print("  HERACLITUS ADVERSARIAL STRESS LAB - STATUS ATUAL")
    print("=" * 60)
    status_icon = "🟢 EM EXECUCAO" if data.get("running") else "🔴 PARADO"
    print(f"  Status do Servico:  {status_icon}")
    print(f"  Perfil Ativo:       {data.get('profile')}")
    print(f"  Iniciado em:        {data.get('started_at')}")
    print(f"  Ultimo Ciclo:       #{data.get('last_cycle', 0)}")
    print(f"  Ultimo Veredito:    {data.get('last_status')}")
    print(f"  Ciclos Concluidos:  {data.get('total_cycles', 0)}")
    print(f"  Ciclos PASS:        {data.get('total_pass', 0)}")
    print(f"  Ciclos FAIL:        {data.get('total_fail', 0)}")
    print(f"  Duracao do Ciclo:   {data.get('last_cycle_duration_sec', 0)}s (Media: {data.get('average_cycle_duration_sec', 0)}s)")
    if data.get("last_error"):
        print(f"  Ultimo Erro:        {data.get('last_error')}")
    print("=" * 60)

if __name__ == "__main__":
    main()
