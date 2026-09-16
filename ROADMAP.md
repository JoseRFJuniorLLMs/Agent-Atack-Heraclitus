# ROADMAP — Agent-Atack-Heraclitus v3

Mapeamento recursivo de lacunas de cobertura adversarial no ecossistema HeraclitusDB.  
Resultado da **Auditoria Recursiva de 10 Iterações** cruzando o harness com a base de código do HeraclitusDB (`crates/`, `lean/`, `qa/`, `sim/`, `fuzz/`).

---

## Matriz de Prioridades

| Módulo Alvo | Vetor de Ataque | Severidade | Status |
| :--- | :--- | :--- | :--- |
| Agent Gateway | Esgotamento de FDs via conexões MCP zumbis (Slowloris) | 🔴 Crítica | ✅ Implementado (v2.0) |
| Agent Gateway | Tool-Call Reentrancy via `_meta` callback | 🔴 Crítica | ✅ Implementado (v2.0) |
| Storage Engine | Torn writes no `.hrkb` durante cortes abruptos de I/O | 🔴 Crítica | ⏳ Pendente |
| Storage Engine | Manifest Poisoning – offset além do EOF | 🔴 Crítica | ✅ Implementado (TC-09 v3) |
| Policy Engine | Bypass por homógrafos Unicode e payloads multiline | 🔴 Alta | ✅ Implementado (v2.0) |
| Policy Engine | YAML Billion Laughs no parser de políticas | 🔴 Alta | ✅ Implementado (v2.0) |
| Ledger/Merkle | Adulteração retroativa de timestamps | 🔴 Alta | ✅ Implementado (v2.0) |
| Raft Cluster | Split-brain em Joint Consensus | 🟠 Alta | ⏳ Pendente |
| Raft Cluster | Replay de mensagens Raft de termos anteriores | 🟠 Alta | ⏳ Pendente |
| Memory / EBR | Epoch Pinning – leitores lentos + rajada de escritas | 🟡 Média | ✅ Implementado (v2.0) |
| HNSW / Vetorial | Degradação de topologia com vetores colineares | 🟡 Média | ⏳ Pendente |
| Temporal Graph | Travessia cíclica com timestamps idênticos | 🟡 Média | ⏳ Pendente |
| Compliance PKI | CRL/OCSP Stalling com cert revogado | 🟡 Média | ⏳ Pendente |
| Compliance PKI | Fuzzing de ASN.1 DER em carimbos de tempo | 🟡 Média | ⏳ Pendente |
| Hume IR / JIT | Query ReDoS / Memory Spilling sem LIMIT | 🟡 Média | ⏳ Pendente |
| Hume IR / JIT | Injeção de opcodes malformados no compilador JIT | 🟡 Média | ⏳ Pendente |

---

## Iteração 1 — Fronteira Agent-Gateway e Interceptação MCP

**O que já existe:** `test_guard.py` foca em payloads básicos de prompt injection e bypass direto de regras textuais. O `heraclitus-agent-gateway` possui testes de permissão estática (`mcp_privacy.rs`).

**O que foi implementado na v2.0:**
- ✅ `unicode_homoglyph_policy_bypass` — `еxec` com cirílico \u0435
- ✅ `multiline_header_injection` — CRLF em campos de metadados MCP
- ✅ `reentrant_tool_call` — `_meta.callback` de exec via reentrância

**O que ainda falta:**
- ⏳ **Injeção de Payloads Fragmentados em SSE/STDIO** — Envio de mensagens MCP JSON-RPC incompletas ou com delimitadores nulos para avaliar se o parser do gateway trava a thread Tokio.

---

## Iteração 2 — Imutabilidade do Log sob Ataque de Escrita Paralela (`heraclitus-log` v6)

**O que já existe:** Fuzz targets em `fuzz_targets/log_decode.rs` e injeção de falhas simuladas em disco (`crc_nao_e_engolido.rs`).

**O que ainda falta:**
- ⏳ **Falsificação de Offset de Cabeçalho (Manifest Poisoning)** — Ataque que grava um manifesto apontando para um offset além do final físico do arquivo (`EOF`), validando se o motor detecta a incongruência sem pânico. *(coberto no TC-09 do v3 contra o stub; falta contra o binário real)*
- ⏳ **Sobrescrita Concorrente em `.hrkb` (Torn Writes com O_DIRECT)** — Escrita simultânea no arquivo de dados enquanto o `packer.rs` consolida blocos selados.

---

## Iteração 3 — Concorrência e Esgotamento de Memória (`heraclitus-memtable`, `ebr.rs`)

**O que já existe:** Testes de carga contínua (`carga_real_1m.rs`, `carga_real_20m.rs`).

**O que foi implementado na v2.0:**
- ✅ `epoch_pinning_concurrent` — 5 leitores lentos + 50 escritas simultâneas

**O que ainda falta:**
- ⏳ **Epoch Pinning em escala real** — 100k transações com leitores EBR presos; requer binário real do HeraclitusDB para medir RSS.
- ⏳ **Contenção no Roll de Índices B-Tree** — Inserção em massa de chaves monotônicas reversas para forçar rebalanceamentos sob concorrência de leitura.

---

## Iteração 4 — Resiliência contra Ataques de Conexão Lenta

**O que foi implementado na v2.0:**
- ✅ `slowloris_fd_exhaustion` — 30 sockets parciais TCP; serviço deve sobreviver

**O que ainda falta:**
- ⏳ **Slowloris em escala real** — Testar com centenas de sockets contra o binário real para medir esgotamento real de FDs via `/proc/{pid}/fd`.

---

## Iteração 5 — Ataques contra o Formato de Bloco v6 (`heraclitus-log`)

**O que foi implementado no v3.0:**
- ✅ TC-09: Manifest Poisoning com payload sintético contra o stub

**O que ainda falta:**
- ⏳ **Injeção de blocos com magic válido mas tamanho divergente** — Requer acesso direto ao arquivo `.hrkb` em tempo de compactação.
- ⏳ **Simulação de bitrot** — Inversão de bits durante ciclo ativo do `packer.rs`.

---

## Iteração 6 — Estresse de Concorrência na MemTable e EBR

**O que foi implementado:**
- ✅ `epoch_pinning_concurrent` via runner.py
- ✅ TC-07 via runner_v3.py (assíncrono)

**O que ainda falta:**
- ⏳ **Injeção de falhas no GC de épocas durante rotação de MemTable** — Requer instrumentação interna do HeraclitusDB.

---

## Iteração 7 — Injeção de Falhas de Partição e Consenso (Raft)

**O que já existe:** Simulação determinística de partição em `sim/heraclitus-sim`.

**O que ainda falta:**
- ⏳ **Split-Brain em Joint Consensus** — Isolamento assimétrico do nó líder exatamente durante fase intermediária de alteração de membros.
- ⏳ **Replay de Mensagens Antigas** — Injeção de `AppendEntries` e `RequestVote` de termos anteriores com payloads corrompidos.

---

## Iteração 8 — Ataques aos Índices Multimodais (Vetorial HNSW e Grafos)

**O que já existe:** Testes de busca e benchmark de limiares adaptativos (`hnsw_search.rs`, `adaptive_threshold.rs`).

**O que ainda falta:**
- ⏳ **Degradação de Topologia HNSW** — Vetores colineares/idênticos em alta taxa concorrente para fragmentar componentes do grafo de busca.
- ⏳ **Travessia Cíclica Temporal** — Grafos de proveniência com timestamps idênticos em ciclos fechados.

---

## Iteração 9 — Fuzzing no Parser de Políticas YAML

**O que foi implementado na v2.0:**
- ✅ `yaml_policy_fuzzing` — Billion Laughs via POST `/api/v1/agent/policies/activate`
- ✅ TC-08 via runner_v3.py — Teste local do parser PyYAML

**O que ainda falta:**
- ⏳ **Estruturas YAML com âncoras circulares** — Testar além das 9 iterações do Billion Laughs (ex: 12+ níveis).

---

## Iteração 10 — Integridade Criptográfica e PKI (`heraclitus-compliance`)

**O que já existe:** Validação sintática RFC 3161 e testes de PKI mockada (`rfc3161.rs`, `test_pki.rs`).

**O que ainda falta:**
- ⏳ **Rejeição de Certificados Revogados (CRL/OCSP Stalling)** — Testar comportamento do validador quando a autoridade de revogação não responde ou retorna certs expirados na cadeia ICP-Brasil.
- ⏳ **Fuzzing de Assinaturas ASN.1 DER** — Injeção de ASN.1 malformado no verificador de carimbos de tempo para checar estouro de buffer.

---

## O que falta para cobertura completa

Para que o `Agent-Atack-Heraclitus` teste o sistema de ponta a ponta, faltam:

1. **Rebuild do HeraclitusDB** — Compilar o binário mais recente com as correções aplicadas após a campanha v1.0.
2. **Campanha massiva v2.0 + v3.0** — Executar ambos os runners contra o binário corrigido.
3. **Relatório final "ele ainda sangra?"** — Comparar os resultados com o baseline da campanha v1.0 (17/17 testes).
4. **Simulação multi-nó Raft** — Usar `sim/heraclitus-sim` para testes de partição e consensus.
5. **Integração com `heraclitus-cli verify`** — Passo pós-ataque automatizado para atestar integridade física do disco.

---

*Gerado automaticamente a partir do fazer.md — Auditoria Recursiva de 10 Iterações.*
