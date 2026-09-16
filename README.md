# Agent-Atack-Heraclitus V3

V3 é a campanha adversarial modular do HeraclitusDB. O harness continua **loopback-only por construção**: Core REST, Agent API, OTLP, MCP Gateway e upstream sintético precisam apontar para `localhost`, `127.0.0.1` ou `::1`. Não existe escape para alvo remoto.

## O que mudou

A V2 era essencialmente uma bateria de probes no `runner.py`. A V3 separa fronteiras porque segurança de protocolo, concorrência, storage físico e consenso são problemas diferentes.

```text
v3_runner.py
attacks/
  common.py       transporte, IDs, upstream delta, evidência
  gateway.py      Unicode, method confusion, reentrancy, policy race, approvals
  protocol.py     duplicate keys, NUL, partial body, chunked fragmentation
  resource.py     conexões lentas limitadas, churn, RSS/threads/FDs
  storage.py      bitrot/truncation SOMENTE em cópia descartável marcada
  source.py       orquestra adversarial suites internas do HeraclitusDB
  raft.py         matriz de consenso/failover
  indexes.py      matriz HNSW/grafo temporal
  compliance.py   matriz RFC3161/DER/Merkle
  query.py        matriz Hume IR/kernel/JIT
metrics/process_probe.py
integrity/verify.py
reporting.py
```

## Suites

### Edge, padrão seguro

```bash
./run_v3.sh config.example.json --suite edge
```

Inclui homógrafos Unicode e zero-width em nomes de tools, divergência `mcp-method` versus corpo JSON-RPC, reentrância na mesma sessão, corrida de consumo de approval, duplicate JSON keys, NUL framing, conexão interrompida durante body, request chunked fragmentado e confusão de `Content-Type`.

### Stress local

```bash
./run_v3.sh config.example.json --suite stress --stress --server-pid "$(cat /path/to/heraclitus.pid)"
```

Executa campanha multiagente mista, corrida com policy reload inválida, conexões lentas limitadas e churn TCP. A V3 mede RSS, número de threads e descritores em Linux quando um PID é fornecido. Os limites são deliberadamente finitos.

### Auditoria de código-fonte Heraclitus

```bash
./run_v3.sh config.example.json --suite source --source-dir ../HeraclitusDB
```

Orquestra suites reais dos crates `heraclitus-raft`, `heraclitus-core`, `heraclitus-log`, `heraclitus-compliance`, índices e Hume. Para Raft a feature `replication` é ligada explicitamente, porque o próprio crate documenta que `cargo test --workspace` sem a feature pode parecer cobertura apesar de não executar a suíte de consenso.

### Storage destrutivo, apenas cópia descartável

Crie uma **cópia** do diretório de dados e marque-a:

```bash
cp -a /dados/heraclitus /tmp/heraclitus-redteam-copy
touch /tmp/heraclitus-redteam-copy/.heraclitus-redteam-disposable
./run_v3.sh config.example.json --suite destructive \
  --destructive-sandbox /tmp/heraclitus-redteam-copy \
  --source-dir ../HeraclitusDB
```

Sem o marcador `.heraclitus-redteam-disposable`, a V3 recusa tocar nos arquivos. Ela faz bitflip e truncation em um candidato, executa `verify_command` e restaura o arquivo original, conferindo o SHA-256 após a restauração.

## Evidência

Cada cenário recebe um `attack_id`. Quando a SPEC-0079 está disponível, o resultado é enviado para `/api/v1/agent/red-team/events`; isso é **telemetria do harness**, não prova independente. Em paralelo, a V3 consulta a API nativa de evidência configurada por `native_evidence_path`. O relatório diferencia `native_evidence=true`, `false` e `null`.

Todo cenário também mede `upstream_delta` quando o stub está ativo. Um `403` com `upstream_delta=1` é falha.

## Relatórios

Cada execução gera `report.json`, `report.md` e `junit.xml`. Não existe “security score” ornamental. A saída traz PASS, FAIL e o que não pôde ser verificado.

## Credenciais

Nada sensível entra em JSON ou relatório. Use ambiente:

```bash
export HERACLITUS_CORE_USERNAME=admin
read -s HERACLITUS_CORE_PASSWORD && export HERACLITUS_CORE_PASSWORD
read -s HERACLITUS_AGENT_TOKEN && export HERACLITUS_AGENT_TOKEN
```

Para Basic Auth da Agent API, também é aceito `HERACLITUS_AGENT_BASIC='usuario:senha'`.

## Compatibilidade V2

O `runner.py` da V2 continua no repositório para campanhas `smoke/full/massive`. A V3 entra por `v3_runner.py` e `run_v3.sh`, permitindo comparar resultados sem quebrar scripts existentes.
