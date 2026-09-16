# Agent-Atack-Heraclitus v3

Suíte adversarial **autorizada, sintética e loopback-only** para qualificar o HeraclitusDB em uma máquina de desenvolvimento. O nome do repositório mantém a grafia original `Atack`.

A v3 nasceu de uma auditoria recursiva cruzando o código do HeraclitusDB com a suíte v2. Em vez de apenas adicionar volume, ela procura **divergências de interpretação entre camadas**: header versus corpo JSON-RPC, identidade declarada versus autenticada, policy versus ação efetivamente encaminhada, headers de entrada versus headers que escapam para o upstream e limite configurado versus memória realmente consumida.

## Regra de segurança do projeto

O runner aceita somente `localhost`, `127.0.0.1` e `::1`. Não existe `--allow-remote`. Há limites rígidos para agentes, concorrência, iterações e tamanho de payload. O stub MCP nunca executa shell, filesystem, subprocessos ou rede externa. `exec` usa apenas marcadores inofensivos como `echo SAFE_MARKER`, que o stub registra mas nunca executa.

O stub também **nunca grava valores de Authorization**. Para probes de credential leakage ele registra apenas `true/false` indicando se determinado header chegou ao upstream. Segurança que testa vazamento copiando o segredo para outro log seria um gênero de comédia que podemos dispensar.

## O que já existia na v2

A base continua cobrindo REST auth, exposição gRPC, OTLP JSON/protobuf malformed e oversized, `tools/call` deny/allow, JSON-RPC batch, Unicode/case/whitespace, duplicate keys, colisões de identidade, approval single-use/replay/mutation/cross-agent/race, carga ALLOW+DENY concorrente, swarm multiagente, fault injection de upstream, policy reload inválida, path traversal de bundles, headers oversized e health do evidence plane.

## Novos ataques da v3

A nova camada acrescenta:

- **`mcp-header-body-method-mismatch`**: header diz `ping`, corpo contém `tools/call/exec`;
- **`mcp-header-body-tool-mismatch`**: header diz `lookup_vendor`, corpo contém `exec`;
- **`mcp-bom-parser-differential`**: JSON com UTF-8 BOM para procurar fail-open entre parsers;
- **JSON scalar/null fail-closed**: corpos que não são objetos JSON-RPC não podem virar passthrough;
- **`gateway-auth-boundary`**: deployment autenticado não deve aceitar chamada MCP sem credencial;
- **`authorization-header-boundary`**: token do caller nunca pode atravessar para o MCP upstream;
- **`connection-nominated-hop-header`**: testa header hop-by-hop nomeado dinamicamente por `Connection`;
- **policy para `resources/read` e `prompts/get`**: métodos data-bearing não podem escapar de ENFORCE;
- **limite de correlation headers**: 513 bytes deve falhar antes de policy/upstream quando o hardening está ativo;
- **upstream response > 8 MiB**: o gateway deve recusar e continuar saudável;
- relatório da auditoria em [`AUDIT-RECURSIVE.md`](AUDIT-RECURSIVE.md).

Esses testes foram criados comparando o `main` atual do HeraclitusDB com a linha de hardening da PR #25. Isso permite usar a suíte de duas formas: reproduzir sangue em uma versão anterior e provar que a correção continua funcionando numa versão posterior.

## Perfis

`smoke` roda a base curta e os diferenciais mais importantes. `full` executa o conjunto recomendado para desenvolvimento. `massive` combina a carga multiagente da v2 com todos os gates v3.

```bash
python3 runner_v3.py --config config.example.json --profile smoke
python3 runner_v3.py --config config.example.json --profile full
python3 runner_v3.py --config config.example.json --profile massive
```

Para rodar **somente os ataques novos**:

```bash
python3 runner_v3.py --config config.example.json --profile full --only-v3
```

Também é possível ajustar a carga dentro dos limites rígidos herdados da v2:

```bash
python3 runner_v3.py --config config.example.json \
  --profile massive --agents 48 --iterations 10 --concurrency 48
```

## Credenciais

Credenciais não entram no JSON de configuração nem nos relatórios.

```bash
export HERACLITUS_CORE_USERNAME='admin'
read -s HERACLITUS_CORE_PASSWORD && export HERACLITUS_CORE_PASSWORD

read -s HERACLITUS_AGENT_TOKEN && export HERACLITUS_AGENT_TOKEN
```

A v3 usa uma credencial **sintética e falsa** no teste de forwarding de Authorization, justamente para não expor a variável acima ao stub.

## Demo local

Suba o HeraclitusDB com o MCP Gateway apontando para o stub local em `127.0.0.1:19000`. Em outro terminal:

```bash
python3 stub_upstream.py --port 19000
./run_demo.sh config.example.json full
```

Campanha pesada:

```bash
./run_demo.sh config.example.json massive
```

O script primeiro executa os testes do próprio atacante e `py_compile`. Só depois inicia a campanha. Humanos chamam isso de paranoia; sistemas que guardam evidência chamam de terça-feira.

## Stub MCP v3

O stub expõe:

```text
GET  /hits   contador global
GET  /stats  hits, by_method, by_tool e últimas chamadas
POST /reset  zera somente o estado sintético
```

Cada item de `last` inclui o JSON-RPC `id`, method, tool e **booleans** de presença para alguns headers de fronteira. Nenhum valor de credencial é armazenado.

Fault injection disponível pela tool `lookup_vendor`:

```text
__stub_500__      -> HTTP 500
__stub_delay__    -> atraso sintético curto
__stub_large__    -> resposta ~256 KiB
__stub_too_large__-> resposta ~9 MiB, pouco acima do teto do Gateway
```

## Como interpretar um PASS

Um `403` sozinho continua não provando nada. Para uma ação proibida, o runner exige que o contador correspondente no upstream permaneça em zero. Para approvals concorrentes, exige exatamente uma execução. Para headers, consulta o stub e verifica se o header realmente atravessou. Para resposta oversized, confirma que o gateway recusou e que o Agent API continuou saudável.

A propriedade que interessa é:

```text
DECISÃO DE SEGURANÇA + AUSÊNCIA DE EFEITO PROIBIDO + EVIDÊNCIA
```

não apenas “recebi um status HTTP que parece seguro”.

## Evidência

Quando a API Red Team da SPEC-0079 está ativa, cada resultado é enviado para:

```text
POST /api/v1/agent/red-team/events
```

O relatório mostra o LSN retornado. Esses registros de laboratório devem ser correlacionados com evidência nativa do HeraclitusDB, como `PolicyEvaluated`, `ToolDenied`, approvals e efeitos externos. O depoimento do atacante não substitui a prova nativa.

## Testes do próprio runner

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile runner.py runner_v3.py stub_upstream.py
```

Os testes verificam loopback-only, inexistência de escape remoto, tetos de campanha, presença dos novos vetores, ausência de comandos destrutivos e a regra de que o stub registra somente presença de Authorization, nunca o valor.
