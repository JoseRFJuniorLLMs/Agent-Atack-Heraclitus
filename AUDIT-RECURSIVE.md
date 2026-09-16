# AUDITORIA RECURSIVA v3 — HeraclitusDB × Agent-Atack-Heraclitus

Data: 2026-09-16

## Escopo

Esta auditoria percorreu recursivamente a árvore dos dois repositórios e aprofundou as fronteiras que recebem input não confiável ou decidem se uma ação pode produzir efeito: Core REST/gRPC, Agent API, OTLP HTTP/gRPC, MCP Gateway, parser JSON-RPC, engine de policy, approvals, deduplicação/evidência, Evidence Bundles, cliente de upstream e o próprio runner adversarial.

O objetivo não é declarar o HeraclitusDB “invulnerável”. O objetivo é transformar cada hipótese relevante em uma propriedade reproduzível: **se uma ação deveria ser bloqueada, ela não pode chegar ao upstream; se uma tentativa ocorreu, a evidência deve sobreviver; se duas camadas interpretam o mesmo request de maneira diferente, o caminho deve falhar fechado.**

A auditoria comparou duas realidades do HeraclitusDB:

1. `main`, que ainda contém comportamentos anteriores em algumas trust boundaries;
2. a PR #25 (`gpt56/agent-security-observability`), que já corrige boa parte dos defeitos encontrados pelas campanhas anteriores e serve como alvo esperado para requalificação.

## Mapa recursivo das superfícies

### HeraclitusDB

- `crates/heraclitus-server/src/rest.rs`: Core REST, autenticação e RBAC por rota.
- `crates/heraclitus-server/src/lib.rs`: wiring, listeners, Core gRPC e gates de exposição.
- `crates/heraclitus-server/src/agent_plane.rs`: composição Agent Black Box/Gateway com o engine.
- `crates/heraclitus-agent-gateway/src/api.rs`: Agent API, policy, approvals, bundles e métricas.
- `crates/heraclitus-agent-gateway/src/ingest.rs`: OTLP/HTTP.
- `crates/heraclitus-agent-gateway/src/grpc.rs`: OTLP/gRPC.
- `crates/heraclitus-agent-gateway/src/gateway.rs`: proxy MCP, policy e evidência.
- `crates/heraclitus-agent-gateway/src/upstream.rs`: fronteira de saída do proxy.
- `crates/heraclitus-agent-gateway/src/auth.rs`: identidade e RBAC do plano Agent.
- `crates/heraclitus-agent/src/mcp.rs`: normalização/extracção JSON-RPC/MCP.
- `crates/heraclitus-agent/src/policy/*`: parsing e avaliação determinística de policy.
- `crates/heraclitus-agent/src/action.rs`: approval binding e single-use.
- `crates/heraclitus-agent/src/dedupe.rs`: deduplicação e conflito sem reescrita.
- `crates/heraclitus-agent/src/config.rs`: gates de produção e loopback.
- `crates/heraclitus-agent/src/bundle.rs`, `zip.rs`, `store.rs`: export/provas/persistência.
- componentes storage/log/raft/sentinel/analytics foram mapeados para identificar superfícies externas e operações administrativas; a campanha v3 continua não destrutiva e não altera arquivos HRKL diretamente.

### Agent-Atack-Heraclitus

O runner v2 já cobria auth REST, reachability gRPC, OTLP malformed/oversized, MCP deny/allow, batch JSON-RPC, Unicode/case/whitespace, duplicate keys, identity collision, approval replay/mutation/race, swarms multiagente, upstream faults, policy reload, path traversal, headers oversized e health do evidence plane.

A v3 acrescenta probes derivados diretamente de divergências observadas no código do HeraclitusDB.

## Achados e novos ataques

### A1 — CRITICAL — `mcp-method` pode divergir do corpo JSON-RPC no `main`

No `main`, `mcp::extract_facts` começa pelos headers MCP e só usa `body.method` quando o header não existe. `gateway.rs` decide se existe policy verificando `facts.method == "tools/call"`.

Cenário adversarial sintético:

- header: `mcp-method: ping`;
- corpo: `tools/call` com tool `exec`;
- se o gateway classificar como `ping`, ele entra no passthrough;
- o upstream lê o corpo real e pode executar `exec`.

**Novo probe:** `mcp-header-body-method-mismatch`.

**Invariante:** `exec upstream_delta == 0`.

A PR #25 já muda a arquitetura para tornar o corpo a autoridade e remover os classification hints antes do forwarding. O teste v3 existe para impedir regressão.

### A2 — CRITICAL — `mcp-name` pode relabelar a tool no `main`

O mesmo padrão existe para `mcp-name`: o parser usa o header antes de `params.name`.

Cenário:

- header: `mcp-name: lookup_vendor`;
- body: `name: exec`;
- uma policy poderia autorizar `lookup_vendor` enquanto o upstream executaria `exec`.

**Novo probe:** `mcp-header-body-tool-mismatch`.

**Invariante:** header nunca pode mudar a ação sobre a qual a policy decidiu.

### A3 — CRITICAL — parser differential com JSON ambíguo/BOM

Uma fronteira de autorização não pode transformar “não consegui interpretar” em passthrough. O v3 envia JSON válido precedido por BOM e corpos JSON escalares, verificando o efeito real no stub.

**Novos probes:** `mcp-bom-parser-differential`, `jsonrpc-scalar-string-fail-closed`, `jsonrpc-scalar-number-fail-closed`, `jsonrpc-null-fail-closed`.

A PR #25 adiciona validação explícita do request JSON antes da policy. A campanha passa a exigir que esses formatos não produzam execução no upstream.

### A4 — CRITICAL — identidade do Gateway versus identidade da Console/API

A configuração já possui `identity.mode = oidc` e a API usa `principal_from`, mas o `main` do proxy MCP não autentica a chamada antes de montar `agent_subject`: usa `X-Heraclitus-Agent`, que é fornecido pelo cliente.

A PR #25 introduz validação OIDC no gateway e deriva o agente confiável do principal validado.

**Novo probe:** `gateway-auth-boundary`.

**Invariante:** quando o deployment declara identidade autenticada, uma chamada sem credencial não pode chegar a uma tool permitida.

Em `dev_local` o teste é SKIP, porque loopback aberto é uma escolha explícita desse modo e não deve ser falsamente rotulada como quebra de autenticação.

### A5 — CRITICAL — credencial de entrada pode atravessar para o MCP upstream

No `main`, `UpstreamClient` remove hop-by-hop e `x-heraclitus-*`, mas `Authorization` não faz parte dessa lista. Logo uma credencial apresentada ao gateway pode atravessar a fronteira.

A PR #25 já remove `authorization` antes de chamar o `UpstreamClient`. O stub v3 registra apenas um booleano indicando presença do header, **nunca seu valor**.

**Novo probe:** `authorization-header-boundary`.

**Invariante:** `Authorization` do caller nunca aparece no upstream.

O probe usa `Bearer REDTEAM_SENTINEL_NOT_A_SECRET`, não a credencial real do operador.

### A6 — HIGH — headers nomeados por `Connection` não são removidos dinamicamente

O cliente de upstream filtra uma lista estática de hop-by-hop headers. HTTP permite que `Connection` nomeie outros headers hop-by-hop daquele request. Exemplo sintético:

`Connection: X-Redteam-Hop`

`X-Redteam-Hop: synthetic-hop-sentinel`

A lista estática remove `Connection`, mas pode deixar `X-Redteam-Hop` atravessar.

**Novo probe:** `connection-nominated-hop-header`.

Este achado permanece relevante também para a versão da PR #25 no momento da auditoria.

### A7 — HIGH — cobertura de policy para métodos MCP não-tool com dados

No `main`, tudo que não é `tools/call` passa sem policy e sem evidência. Isso inclui métodos que podem carregar/ler dados, como `resources/read` e `prompts/get`.

A PR #25 distingue métodos de controle de métodos data-bearing e nega estes últimos em `shadow/enforce`.

**Novos gates v3:** `protocol-data-policy-resources/read` e `protocol-data-policy-prompts/get`.

`config.example.json` usa `expect_data_methods_blocked: true`, porque esse é o comportamento alvo após o hardening.

### A8 — HIGH — limite de correlation headers

Headers como Agent, Run, User, Environment e Trace viram metadados persistidos. Input sem limite pode virar amplificação de memória/log ou identidade grotescamente grande.

A PR #25 adiciona teto de 512 bytes.

**Novo probe:** `correlation-header-513-boundary`.

**Invariante alvo:** 513 bytes falham antes de policy/upstream com reason code de input/header inválido.

### A9 — HIGH — limite do corpo de resposta precisa valer durante a leitura

No `main`, o `UpstreamClient` coleta a resposta inteira e só depois verifica `max_response_bytes`. Isso limita o que é aceito, mas não limita a alocação de pico causada por um upstream comprometido.

A PR #25 já muda para leitura por frames e aborta assim que o teto é ultrapassado.

O stub v3 oferece `__stub_too_large__`, resposta sintética de aproximadamente 9 MiB, deliberadamente pouco acima do limite de 8 MiB.

**Novo probe:** `upstream-response-size-limit`.

**Invariante:** resposta recusada e Agent API continua saudável.

### A10 — HIGH — conflito de deduplicação e evidência de retries

A dedupe lógica não inclui `agent_id` e, sem trace/span, usa `tool_call_id`. No `main`, um conflito pode virar `Gravacao::Ok(None)` e a chamada continuar. Isso já foi encontrado em campanha real anterior no fluxo de approval.

A PR #25 contém hardening específico e campanhas 128-way/4096-way. A v3 mantém colisões multiagente e approval races do v2 para garantir que a correção permaneça verdadeira quando combinada aos novos probes.

### A11 — MEDIUM — simulação histórica perde `environment`

`api.rs::input_from_evidence` reconstrói `PolicyInput` com `environment: None`. Uma policy candidata dependente de ambiente pode, portanto, produzir uma simulação histórica diferente da decisão original.

Isso é principalmente um defeito de fidelidade/auditoria, não um bypass direto de runtime. Foi registrado para correção no HeraclitusDB, mas não virou exploit de rede nesta versão do runner.

### A12 — MEDIUM — `/v1/metrics` e `/v1/logs` não passam pelo mesmo `ingest_gate`

O OTLP HTTP aplica autenticação em `/v1/traces`, enquanto métricas/logs são aceitos e descartados diretamente. Como esses endpoints não persistem evidência, não existe injeção no HRKL, mas a semântica de “OTLP require_auth” fica inconsistente entre sinais.

Mantido como achado de hardening/documentação, não como vulnerabilidade de integridade do log.

## Controles que permaneceram bons

A auditoria também confirmou decisões defensivas que merecem continuar como invariantes:

- defaults de policy são deny e `defaults.decision: allow` é recusado;
- comparação monetária da policy evita `f64`;
- Evidence Bundle usa nome gerado pelo servidor e download rejeita segmentos suspeitos;
- OTLP/gRPC aplica a mesma credencial quando `require_auth` está ligado;
- Core REST/gRPC possuem gates para evitar exposição pública sem auth;
- upstream não faz redirect automático nem retry automático de tool call;
- `x-heraclitus-*` é removido antes de chegar ao upstream;
- produção exige OIDC no Agent Gateway e bypass protection declarado em ENFORCE;
- runner adversarial continua sem `--allow-remote` e com limites rígidos.

## Matriz v3

| Vetor | Classe | Efeito proibido |
|---|---|---|
| `mcp-header-body-method-mismatch` | parser/policy differential | `exec` chegar ao upstream |
| `mcp-header-body-tool-mismatch` | action relabeling | `exec` chegar ao upstream |
| `mcp-bom-parser-differential` | parser differential | request ambíguo virar passthrough |
| JSON scalars/null | fail-open parsing | qualquer upstream hit |
| `gateway-auth-boundary` | identity | caller não autenticado usar allow |
| `authorization-header-boundary` | credential leakage | Authorization chegar ao stub |
| `connection-nominated-hop-header` | proxy semantics | header hop-by-hop dinâmico escapar |
| `protocol-data-policy-*` | policy coverage | data method escapar de ENFORCE |
| `correlation-header-513-boundary` | resource/identity limit | header sem limite persistir/seguir |
| `upstream-response-size-limit` | memory resilience | resposta > limite ser aceita / matar gateway |

## Critério de sangue

A campanha v3 considera que “o herói ainda sangra” quando qualquer uma destas coisas acontece:

1. ação proibida produz `upstream_delta > 0`;
2. credencial/correlation metadata cruza uma fronteira onde não deveria;
3. aprovação executa mais de uma vez ou cruza identidade;
4. parser inválido/ambíguo vira passthrough;
5. método data-bearing evita policy em ENFORCE;
6. ataque quebra listener/health;
7. evento esperado não ganha evidência/LSN quando a SPEC-0079 está disponível.

Um HTTP 403 isolado não é considerado prova de segurança. O stub mede efeito real.

## Execução

```bash
python3 stub_upstream.py --port 19000
./run_demo.sh config.example.json full
./run_demo.sh config.example.json massive
```

Somente os probes novos:

```bash
python3 runner_v3.py --config config.example.json --profile full --only-v3
```

A saída gera JSON e Markdown em `reports/`.
