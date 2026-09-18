# V3 Full-Stack Extension

A V3 já integrada ao `main` cobre as trust boundaries do Agent Gateway. Esta extensão cobre as lacunas fora da borda HTTP/MCP sem substituir o runner atual.

## Cobertura adicionada

- **Protocol framing:** request HTTP/1 chunked fragmentado e conexão que desaparece no meio do body.
- **Resource pressure:** slow clients limitados e connect/disconnect churn, com medição opcional de RSS, VM, threads e FDs por `/proc/<pid>`.
- **Recursive source qualification:** executa suites reais dos crates de Raft, EBR, HLC, log v6, RFC3161/receipts, HNSW, grafo temporal e Hume IR/kernel.
- **Raft:** `--features replication` é obrigatório no probe porque o próprio `heraclitus-raft` documenta que o teste workspace padrão pode executar zero testes de consenso.
- **Storage integrity:** bitflip e truncation apenas em cópia descartável marcada com `.heraclitus-redteam-disposable`. Após cada mutação roda `cargo run -p heraclitus-cli -- storage doctor <clone>`, restaura o arquivo e confirma SHA-256.
- **Relatórios:** JSON, Markdown e JUnit XML.

## Execução

Gateway + framing:
```bash
python3 runner_v3_fullstack.py --config config.example.json --suite edge --profile full
```

Pressão de recursos local:
```bash
python3 runner_v3_fullstack.py --config config.example.json --suite resource --server-pid "$(cat /tmp/heraclitus.pid)"
```

Auditoria recursiva de source:
```bash
python3 runner_v3_fullstack.py --config config.example.json --suite source --source-dir ../HeraclitusDB
```

Storage destrutivo em **clone descartável**:
```bash
cp -a /dados/heraclitus /tmp/heraclitus-redteam-copy
touch /tmp/heraclitus-redteam-copy/.heraclitus-redteam-disposable
python3 runner_v3_fullstack.py --config config.example.json --suite destructive --source-dir ../HeraclitusDB --destructive-sandbox /tmp/heraclitus-redteam-copy
```

`all` exige `--source-dir` e `--destructive-sandbox`, precisamente para ninguém descobrir que digitou o diretório de produção depois de ouvir o barulho do disco.

## O que não é falsamente alegado

- O harness não altera o relógio do host. HLC é qualificado pelos testes sintéticos do crate.
- CRL/OCSP externo não é fabricado se a infraestrutura de teste não existir.
- SSE/STDIO não são inventados como superfície se o deployment expõe apenas HTTP MCP.
- O harness usa a suíte Raft do próprio Heraclitus para links cortáveis, failover, quorum, snapshots e restart.
