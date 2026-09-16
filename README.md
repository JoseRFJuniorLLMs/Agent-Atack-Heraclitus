# Agent-Atack-Heraclitus

Laboratório adversarial **autorizado e loopback-only** para HeraclitusDB. O nome mantém a grafia solicitada do projeto (`Atack`). A ferramenta faz requisições reais contra Core REST, Agent API, OTLP e MCP Gateway, mede o efeito no upstream sintético e envia apenas metadados seguros para `POST /api/v1/agent/red-team/events`.

---

## Regra de segurança

O runner encerra antes de qualquer teste se um endpoint não for `localhost`, `127.0.0.1` ou `::1`. **Não existe flag `--allow-remote`**. O stub não executa comandos, filesystem, subprocessos ou chamadas externas. Ferramentas perigosas usam apenas marcadores inofensivos como `echo HERACLITUS_REDTEAM_SHOULD_NOT_EXECUTE`.

---

## Estrutura do projeto

```
Agent-Atack-Heraclitus/
├── runner.py              ← Harness adversarial principal (v2.0 — 22 ataques)
├── runner_v3.py           ← Harness de resiliência e telemetria (v3.0 — 10 TCs assíncronos)
├── stub_upstream.py       ← Mock MCP upstream com modos adversariais
├── config.example.json    ← Configuração de exemplo
├── run_demo.sh            ← Script de demo rápido
├── tests/
│   ├── test_guard.py          ← Guardrails, loopback, Unicode, presença de vetores
│   ├── test_reporting.py      ← Geração e validação de relatórios JSON/Markdown
│   └── test_v3.py             ← Guardrails do harness v3 (AdvancedLab)
├── docs/
│   ├── AUDIT-RECURSIVE.md     ← Achados A1–A12 da auditoria recursiva v3
│   └── ROADMAP.md             ← Matriz de prioridades e lacunas por iteração
└── reports/               ← Relatórios gerados em runtime (JSON + Markdown)
```

---

## Ataques cobertos (v2.0 — `runner.py`)

### Originais (v1.0)

| Vetor | Alvo | O que prova |
| :--- | :--- | :--- |
| `core-no-auth` | Core REST | HTTP 401 sem credenciais |
| `core-bad-auth` | Core REST | HTTP 401 com credenciais erradas |
| `grpc-reachability` | gRPC surface | Exposição TCP sem provar auth |
| `otlp-malformed-json` | OTLP | Rejeição 400 + listener sobrevive |
| `otlp-oversized` | OTLP | HTTP 413 em payload acima do limite |
| `mcp-policy-deny` | MCP Gateway | `exec` bloqueado (403) + upstreamΔ=0 |
| `mcp-benign-allow` | MCP Gateway | `lookup_vendor` permitido + upstreamΔ=1 |
| `jsonrpc-batch-bypass` | MCP Gateway | Batch misto não bypassa deny |
| `protocol-resources/read` | MCP Gateway | Cobertura de evidência |
| `protocol-prompts/get` | MCP Gateway | Cobertura de evidência |
| `approval-single-use` | MCP Approval | pending→approve→execute once→replay deny |
| `approval-binding-mutation` | MCP Approval | Args mutados invalidam approval |
| `concurrent-deny-flood` | MCP Gateway | 64x 403 sem upstreamΔ |
| `invalid-policy-reload` | Agent API | Policy inválida não substitui a ativa |
| `bundle-path-traversal` | Agent API | Path traversal bloqueado |
| `oversized-identity-header` | MCP Gateway | Header 16KiB + health check |

### Novos (v2.0)

| Vetor | Iteração | Severidade | O que prova |
| :--- | :--- | :--- | :--- |
| `unicode-homoglyph-bypass` | IT-1 | 🔴 Alta | `еxec` com 'е' cirílico bloqueado como `exec` |
| `multiline-header-injection` | IT-1 | 🟠 Alta | CRLF em campo vendor não quebra parser |
| `reentrant-tool-call` | IT-2 | 🔴 Alta | `_meta.callback.exec` ignorado pelo gateway |
| `rate-limit-burst` | IT-2 | 🟡 Média | 100 req/s → mede throttling por sessão |
| `merkle-timestamp-forgery` | IT-3 | 🔴 Alta | Evento com timestamp=2000 rejeitado/ignorado |
| `slowloris-fd-exhaustion` | IT-4 | 🔴 Crítica | 30 sockets parciais → serviço sobrevive |
| `epoch-pinning-concurrent` | IT-6 | 🟡 Média | 5 readers lentos + 50 escritas → sem OOM |
| `yaml-policy-fuzzing` | IT-9 | 🔴 Alta | YAML Billion Laughs rejeitado pelo parser |

---

## Baterias assíncronas de resiliência (v3.0 — `runner_v3.py`)

| TC | Descrição | Severidade |
| :--- | :--- | :--- |
| TC-01 | Timeout em canais inativos e limpeza de sockets | Alta |
| TC-02 | Sanitização de homóglifos Unicode em Policies | Alta |
| TC-03 | Resiliência a JSON truncado e bytes nulos | Alta |
| TC-04 | Carga concorrente (30 clientes simultâneos) | Média |
| TC-05 | Verificação física Merkle / `heraclitus-cli verify` | Crítica |
| TC-06 | Slowloris FD Exhaustion – conexões MCP zumbis | Crítica |
| TC-07 | Epoch Pinning – MemTable OOM por leitores presos | Média |
| TC-08 | YAML Billion Laughs – exaustão CPU/memória | Alta |
| TC-09 | Manifest Poisoning – offset além do EOF | Crítica |
| TC-10 | Tool-Call Reentrancy via MCP `_meta` callback | Crítica |

---

## Status da campanha

```
Agent-Atack-Heraclitus
        ✅ v1.0 executado
        ✅ 17/17 probes na campanha original
        ✅ encontrou bug real no HeraclitusDB (evidência sealed no HRKL)
        ✅ v2.0 implementado (+8 novos ataques)
        ✅ v3.0 harness assíncrono (+10 TCs com telemetria)

HeraclitusDB (próximo passo)
        ✅ código corrigido após campanha v1.0
        ❌ rebuild local final pendente
        ❌ campanha massiva v2.0+v3.0 contra build corrigido pendente
        ❌ relatório final "ele ainda sangra?" pendente
```

**Próximo passo**: fazer rebuild do HeraclitusDB e executar `runner.py` (v2.0) + `runner_v3.py` (v3.0) contra o binário corrigido para gerar o relatório definitivo.

---

## Credenciais

Nunca entram em arquivo de configuração nem no relatório.

```bash
# Core REST
export HERACLITUS_CORE_USERNAME='admin'
read -s HERACLITUS_CORE_PASSWORD && export HERACLITUS_CORE_PASSWORD

# Agent API com OIDC/Bearer
read -s HERACLITUS_AGENT_TOKEN && export HERACLITUS_AGENT_TOKEN
```

---

## Execução rápida

### Demo com stub (totalmente sintético)

```bash
# Terminal 1: stub adversarial
python3 stub_upstream.py --port 19000

# Terminal 2: runner adversarial (22 ataques)
python3 runner.py --config config.example.json

# Terminal 3: harness de resiliência (10 TCs assíncronos)
python3 runner_v3.py --host 127.0.0.1 --port 9000
```

### Mudar modo do stub em tempo real

```bash
# Simula upstream lento (força timeout)
curl -X POST http://127.0.0.1:19000/mode/delayed

# Simula upstream malformado
curl -X POST http://127.0.0.1:19000/mode/malformed

# Restaura modo normal
curl -X POST http://127.0.0.1:19000/mode/normal

# Ver hits
curl http://127.0.0.1:19000/hits
```

### Testes unitários

```bash
python3 -m pytest tests/ -v
```

---

## Evidência, sem truques

`redteam_lab` é o depoimento do runner selado no HRKL. Ele deve ser correlacionado com evidência nativa do HeraclitusDB como `PolicyEvaluated`, `ToolDenied`, approvals e `ExternalEffectObserved`. O Dashboard R10 mostra essa diferença explicitamente.