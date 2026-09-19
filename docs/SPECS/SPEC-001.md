# SPEC-001-CORECOES.md

**Matriz Canônica e Exaustiva de Ataques, Resiliência Física e Caos**

**Alvos:** `HeraclitusDB` (Core Rust, Hume JIT IR, Storage HRKL/HRKB/Manifest, EBR/MemTable, Raft Consensus, Agent Plane/MCP) × `Agent-Atack-Heraclitus` (SuperRunner v4, Harness v3, Massive v2/v3, Invocadores & Oráculos)

**Assinatura de Segurança:** Loopback-Only Enforced (`127.0.0.1`, `::1`, `localhost`), Zero False-PASS Oracle Model, Strict Upstream Effect Tracking ($\Delta = 0$).

---

## 1. Plano de Ação Imediato: Implementação dos Gaps Críticos

### 1.1 Injeção Física Real no Consenso Raft (`src/chaos/raft_chaos.py`)

* **Eliminação do Stub `time.sleep`:** Substituir a simulação estática por controle de conectividade assíncrona local (bloqueio ativo de descritores de socket TCP loopback ou isolamento de portas gRPC via regras de filtragem).
* **Partição Assimétrica na Transição de Joint Consensus:** Monitorar a fase em que a configuração do cluster muda de $C_{\text{old}}$ para $C_{\text{old,new}}$ e disparar o isolamento do líder do termo. Validar se o cluster paralisa comutação com segurança em vez de registrar transações com logs bifurcados (Split-Brain com $\text{committed\_divergence} > 0$).
* **Tempestade de Eleição (Split-Vote Storm):** Introduzir jitter assimétrico nas mensagens de heartbeat (`AppendEntries`) e requisição de votos (`RequestVote`), forçando timeouts simultâneos em múltiplos nós seguidores para medir a resiliência do backoff aleatório.

### 1.2 Validação de Limites Físicos no Armazenamento (`src/chaos/storage_tamper.py`)

* **Dirty Page Racing vs Instant SIGKILL:** Disparar rajada contínua de inserções e enviar `SIGKILL -9` imediatamente após o retorno do ACK pelo Gateway. Validar via `heraclitus storage doctor` se as páginas sujas retidas no buffer do Linux foram realmente persistidas via `fsync`/`fdatasync` nos arquivos `.hrkl` e `.manifest`.
* **Sparse File Injection (Hole Punching / Zero-Fill Attack):** Substituir intervalos intermediários de blocos `.hrkb` por sequências contínuas de `\x00` (`fallocate -p`) preservando tamanho e cabeçalho. Comprovar que os validadores de integridade CRC e raízes Merkle rejeitam o bloco como corrompido em vez de interpretar o bloco como dados nulos válidos.
* **Torn Write Concorrente com Compaction:** Provocar truncamento em `.manifest` exatamente durante a rotação da MemTable para blocos imutáveis `.hrkb`, verificando a restauração atômica sem geração de arquivos órfãos.
* **Simulação de Disco Esgotado (ENOSPC Handling):** Montar o diretório de dados em um volume `tmpfs` limitado a 15 MB e inundar o armazenamento até o limite físico, verificando se o motor entra em modo *Safe Read-Only* sem corrupção irreversível do catálogo.

### 1.3 Fuzzing Profundo do Motor Hume JIT IR (`src/chaos/hume_destructor.py`)

* **AST Deep Recursion (Stack Overflow Fuzzer):** Gerar grafos acíclicos lineares com mais de 20.000 nós unários encadeados (`Not(Not(...(Col)...))`). Validar se o parser/compilador em Rust adota descida recursiva protegida (`stacker`) ou gera terminação anômala por `SIGSEGV` na thread do worker.
* **Type Confusion em Operações Vetoriais SIMD:** Injetar matrizes multidimensionais com dimensões negativas (`[-1, 0]`), casts diretos de ponteiros de strings para inteiros de máquina de 64 bits e identificadores de colunas com valores fora de escala (`0x7FFFFFFFFFFFFFFF`).
* **Divisão por Zero e Overflows Aritméticos em Constant Folding:** Fornecer expressões matemáticas no Hume IR que gerem estouro de limites (`MAX_INT + 1`) ou divisão imediata por zero avaliadas em tempo de compilação.

### 1.4 Exaustão de Memória Concorrente no Gerenciamento EBR (`src/chaos/ebr_stress.py`)

* **EBR Starvation OOM Attack:** Manter múltiplos leitores lentos retendo a época ativa por mais de 60 segundos enquanto centenas de workers em paralelo realizam rotações massivas de MemTable. Avaliar se o `delta_rss_mb` dispara linearmente até o colapso pelo Linux OOM Killer ou se o motor aplica *backpressure* nas gravações.
* **Use-After-Free Concorrente na Virada de Época:** Executar leituras contínuas em chaves que sofrem deleção e sobregravação simultânea no momento exato do incremento do contador global de época, auditando ausência de acesso a ponteiros liberados no heap.
* **Desbalanceamento Patológico de B-Tree:** Submeter 50.000 chaves ordenadas de forma monotonicamente decrescente combinadas com prefixos idênticos de 1024 bytes, forçando fragmentação contínua e múltiplos *splits* em nós de topo.

### 1.5 Blindagem na Camada HTTP / REST e Validação de Credenciais

* **HTTP Request Smuggling & CRLF Injection:** Testar combinações anômalas de cabeçalhos `Transfer-Encoding: chunked` e `Content-Length` duplicados na porta Core REST, validando rejeição estrita de framing ambíguo.
* **Timing Attacks Estatísticos em Autenticação:** Realizar amostragem estatística de latência (testes $t$ de Student) entre senhas com prefixos coincidentes e senhas totalmente aleatórias no cabeçalho `Authorization: Basic`, certificando comparação em tempo constante.

### 1.6 Oráculos Contínuos em Tempo Real (`src/oracles/`)

* **Oráculo de Monotonicidade Estrita em Tempo de Execução:** Interceptar todos os retornos do Gateway no `Lab.request` para garantir que $LSN_{k+1} > LSN_k$ sem gaps não documentados.
* **Conexão do Oráculo de Differential Replay:** Automatizar no `perpetual_runner.py` a reconstrução do estado completo a partir do LSN 0, comparando o digest SHA-256 do estado reidratado com o hash da instância em memória ativa.

---

## 2. Taxonomia Completa de Ataques ao Ecossistema Heraclitus

### Camada 1: Protocolo Agêntico, MCP Gateway e Governança

1. **Descompasso de Verbo MCP (`mcp-method` vs `body.method`):** Cabeçalho declarando `ping` emparelhado com corpo JSON-RPC invocando `tools/call` com ferramenta restrita (`exec`). *Invariante:* $\Delta_{\text{upstream}} = 0$.
2. **Relabeling de Ferramenta via Metadados (`mcp-name` vs `params.name`):** Cabeçalho declarando ferramenta benigna (`lookup_vendor`) e corpo solicitando ferramenta protegida.
3. **Injeção de Byte Order Mark (BOM):** Envio de payloads JSON prefixados por bytes UTF-8 BOM (`\xef\xbb\xbf`), prevenindo que falhas de parsing abram caminho de *passthrough* desgovernado.
4. **JSON-RPC Escalares Puros (Fail-Closed Enforcement):** Envio de tipos primitivos puros (`"raw_string"`, `12345`, `null`, `[]`) no corpo da requisição MCP.
5. **Sequestro de Contexto via `_meta` Callback (Tool-Call Reentrancy):** Injeção de nós `_meta.callback` apontando para ferramentas administrativas.
6. **Vazamento de Credenciais em Fronteiras de Proxy:** Verificação de que o cabeçalho `Authorization` apresentado ao gateway pelo operador é expurgado antes do redirecionamento ao stub upstream.
7. **Cabeçalhos Hop-by-Hop Dinâmicos (`Connection: X-Custom-Header`):** Envio de diretivas dinâmicas na cláusula `Connection`, garantindo higienização de cabeçalhos intermediários.
8. **Evasão de Governança em Métodos Não-Tool (`resources/read`, `prompts/get`):** Tentativa de invocar superfícies de leitura de dados sem passar pelas matrizes de autorização de política.
9. **Saturação de Metadados de Correlação (Boundary 513 Bytes):** Injeção de strings de 513 bytes em `X-Heraclitus-Agent`, `X-Heraclitus-Run`, etc., exigindo rejeição HTTP 400 antes do despacho.
10. **Respostas Upstream Hiperdimensionadas (Streaming Truncation):** Forçar o stub upstream a devolver respostas superiores ao teto de 8 MiB para atestar corte de fluxo sem explosão de alocação de memória RAM.

### Camada 2: Políticas, Approvals e Semântica de Execução

11. **Homóglifos Unicode em Políticas:** Uso de caracteres cirílicos idênticos visualmente aos latinos (`\u0430` vs `'a'`, `\u0435` vs `'e'`) para ludibriar regras baseadas em string.
12. **Injeção de Separadores de Largura Zero (ZWSP):** Inserção de `\u200b` em identificadores para corromper regexes e validadores de escopo.
13. **Billion Laughs / YAML Bomb em Definições de Política:** Submissão de matrizes de regras com referências circulares e recursivas de âncoras YAML.
14. **Sequestro de Aprovação entre Agentes Distintos (Cross-Agent Approval Theft):** Agente malicioso tenta consumir identificador de `approval_id` gerado e deferido para outro agente.
15. **Consumo Atômico Concorrente de Aprovações (Race Condition 128-Way):** Disparo simultâneo de dezenas de requisições utilizando a mesma aprovação de uso único, comprovando execução estritamente singular ($N=1$).
16. **Falsificação Estrutural de Tipos em Argumentos Aprovados:** Modificação sutil de argumentos pós-aprovação (ex.: `75000` para `"75000"`, array ou float), exigindo rejeição imediata por quebra de assinatura canônica.
17. **Isolamento de Namespace de Aprovação sob IDs Conflitantes:** Submissão concorrente de approvals idênticos por agentes distintos sem sobreposição de estado interno.
18. **Recarregamento Concorrente de Políticas Inválidas:** Submissão de políticas malformadas durante a execução de rajadas de ferramentas para assegurar atomicidade de snapshot e ausência de estado nulo.

### Camada 3: Motor Hume IR e Compilação JIT

19. **Bypass de Alocação de Memória no IR (Heap Bomb):** Submissão de planos analíticos que forcem alocação de tabelas temporárias gigantescas via estimativa forjada de cardinalidade.
20. **Injeção de Ciclos em Grafos DAG de Execução:** Inserção de dependências circulares veladas entre operadores unários para prender o otimizador em loop infinito.
21. **FFI e Escape de Sandbox JIT:** Tentativas de referenciar endereços de memória direta ou símbolos intrínsecos proibidos via nós de operadores externos.
22. **Injeção de NaN e Infinitos em Agregações Vetoriais:** Envio de valores de ponto flutuante especiais em colunas de agregação para testar propagação de exceções aritméticas sem colapso de thread.

### Camada 4: Memória, Estruturas de Dados e Concorrência

23. **Slowloris FD Exhaustion:** Abertura massiva de conexões parciais sustentadas para exaurir os descritores de arquivo do sistema operacional.
24. **Hotspot Contention em Chave Única:** Rajada de 500 workers concorrentes executando escritas e leituras sobre o mesmo registro atômico.
25. **Zumbis de Transação em Conexões Abortadas (TCP RST):** Envio deliberado de pacotes TCP RST no meio da transação para verificar reciclagem segura de locks e referências EBR.
26. **Exaustão de Pool de Workers por Invocação Reentrante:** Forçar o motor a encadear chamadas bloqueantes internas até esgotar a capacidade de processamento concorrente.

### Camada 5: Armazenamento Físico, Logs e Persistência

27. **Corrupção de Checksum em Cabeçalhos `.hrkb`:** Adulteração cirúrgica de bits nos primeiros 32 bytes do cabeçalho de bloco.
28. **Inconsistência de LSN entre `.manifest` e WAL `.hrkl`:** Dessincronização proposital entre o ponteiro do manifesto e os registros presentes no log físico de escrita ativa.
29. **Fragmentação Severa por Deletions Massivas:** Inserção massiva de dados seguida de deleção de 95% do volume para testar o compactador de disco e integridade das árvores B-Tree.
30. **Truncamento de Bloco Durante Flush Ativo:** Corte físico do tamanho de um bloco no disco durante a sincronização concorrente de arquivos de dump.

### Camada 6: Consenso Distribuído, Raft e Rede

31. **Isolamento de Quórum Estrito ($N/2$ Split):** Corte das linhas de comunicação entre o nó líder e a maioria necessária para sustentação do quórum de escrita.
32. **Heartbeat Flood Denial:** Sobrecarga intencional do canal de batimentos cardíacos com pacotes forjados para simular falsas perdas de conectividade.
33. **Atraso Seletivo de Snapshots:** Injeção de latência extrema na replicação de snapshots completos para nós seguidores defasados.

### Camada 7: Criptografia, Merkle Trees e Conformidade Temporal

34. **Injeção de ASN.1 DER Malformado (RFC 3161):** Cargas úteis criptográficas contendo tamanhos de 4GB (`\x30\x84\xff\xff\xff\xff`) e tags inválidas.
35. **Forjamento Temporal Retroativo e Futuro:** Tentativa de registrar eventos no ledger com timestamps no ano 2000 ou 2099, exigindo recusa pela política de monotonicidade.
36. **Adulteração de Folhas em Árvores Merkle Ímpares:** Provar detecção de tamper quando a quantidade de folhas requer duplicação da última folha intermediária.
37. **Ataques de Extensão de Comprimento em Hashing de Bloco:** Forjar sufixos em dados encadeados sem invalidar a raiz hash computada.

### Camada 8: Superfície Administrativa, Telemetria e Auditoria

38. **Fuzzing de Framing Protobuf no Core gRPC:** Injeção de mensagens de Protocol Buffers com estruturas varint corrompidas diretamente na porta 17474.
39. **Esgotamento de Streaming OTLP Lento:** Manter streams OTLP abertos transmitindo dados a 1 byte por segundo para imobilizar threads de ingestão de telemetria.
40. **Controle de Escala em Consultas Red-Team (`limit=999999`):** Submeter parâmetros de consulta excessivos no endpoint `/api/v1/agent/red-team/events`, atestando aplicação de teto estrito de paginação sem amplificação de resposta em memória.

---

## 3. Matriz Operacional dos 40 Vetores

| ID | Vetor de Ataque | Camada Alvo | Condição de Falha (Sangramento) | Invariante de Sucesso |
| --- | --- | --- | --- | --- |
| **V01** | MCP Header/Body Method Mismatch | Gateway | Upstream recebe `exec` | Rejeição 400/422; $\Delta_{\text{upstream}} = 0$ |
| **V02** | MCP Header/Body Tool Relabeling | Gateway | Upstream recebe ação disfarçada | Rejeição 400/422; $\Delta_{\text{upstream}} = 0$ |
| **V03** | UTF-8 BOM Parser Differential | Parsing | Interpretação vira passthrough | Rejeição controlada sem passthrough |
| **V04** | Scalar JSON-RPC Payloads | Parsing | Erro 500 ou execução acidental | Rejeição limpa HTTP 400 |
| **V05** | Tool-Call Reentrancy (`_meta`) | Gateway | Execução de shell pelo callback | Callback ignorado; $\Delta_{\text{upstream}} = 0$ |
| **V06** | Upstream Credential Stripping | Auth/Proxy | Token Bearer alcança upstream | Token removido nos headers de saída |
| **V07** | Connection Hop-by-Hop Nomination | Proxy | Cabeçalhos internos vazam | Remoção dinâmica de hop headers |
| **V08** | Non-Tool Data Surface Policy | Governança | `resources/read` executa sem log | Bloqueio em modo ENFORCE |
| **V09** | Correlation Header Overflow | Gateway | Header $\ge 513$ bytes persiste | Rejeição prévia com HTTP 400 |
| **V10** | Upstream Oversized Stream | Gateway | Alocação $> 8\text{ MiB}$ em RAM | Aborto imediato de leitura por frame |
| **V11** | Homóglifo Cirílico em Tool Name | Governança | `еxec` passa filtros de policy | Normalização NFKC bloqueia ação |
| **V12** | Injeção de Espaços Zero-Width | Governança | `ex\u200bec` evade regex de policy | Sanitização prévia à validação |
| **V13** | YAML Billion Laughs Policy Bomb | Parsing | OOM ou hang no parser de política | Parser aborta com profundidade limitada |
| **V14** | Cross-Agent Approval Theft | Approvals | Ladrão consome aprovação alheia | Rejeição 403; aprovação vinculada |
| **V15** | Corrida de Approval 128-Way | Approvals | Execuções simultâneas $> 1$ | Exatamente 1 sucesso e 127 rejeições |
| **V16** | Falsificação de Tipo em Approval | Approvals | `amount: 75000` mutado para float | Quebra de assinatura; recusa 403 |
| **V17** | Approval Namespace Collision | Approvals | Colisão de IDs entre agentes | IDs de aprovação rigorosamente únicos |
| **V18** | Recarregamento de Política Inválida | Config | Configuração anterior é anulada | Snapshot ativo permanece imutável |
| **V19** | Hume IR Heap Bomb | JIT / Engine | Alocação desmedida sem limite | Falha com erro de limite de memória |
| **V20** | Ciclos em Grafo DAG Hume IR | JIT / Engine | Thread de compilação em 100% CPU | Detecção de ciclo com erro 400 |
| **V21** | FFI Sandbox Escape no JIT | JIT / Engine | Acesso a primitivas restritas | Falha de compilação por símbolo inválido |
| **V22** | Floating Point NaN Vector Flooding | JIT / Engine | Pânico na thread de computação | Tratamento IEEE 754 sem crash |
| **V23** | Slowloris Socket Exhaustion | Rede | Porta deixa de responder liveness | Limpeza de sockets inativos; liveness OK |
| **V24** | Hotspot Single-Key Contention | Memória | Leitura de dado inconsistente | Atomicidade MVCC/Lock preservada |
| **V25** | TCP RST Abrupt Termination | Memória | Descritores órfãos no EBR | Desalocação atômica de contexto |
| **V26** | AST Recursion Deep Stack Fuzzing | JIT / Engine | Estouro de thread stack (SIGSEGV) | Execução com stack protegida |
| **V27** | Storage Header Bit-Flip | Storage | Bloco corrompido aceito | Doctor/Verify detecta CRC inválido |
| **V28** | Dessincronização de Manifesto | Storage | LSN divergente sobrescreve log | Inicialização aborta por inconsistência |
| **V29** | Fragmentação Severa de B-Tree | Storage | Perda de integridade nos nós | B-Tree rebalanceada sem corrupção |
| **V30** | Truncamento Concorrente de Bloco | Storage | Log persistido corrompe na inicial | Rollback atômico até ponto consistente |
| **V31** | Partição Raft Joint Consensus | Consenso | Logs bifurcados no cluster | Cluster congela sem split-brain |
| **V32** | Heartbeat Flood Denial | Consenso | Falsas eleições em cascata | Estabilidade de termos preservada |
| **V33** | Atraso Crítico em Snapshots | Consenso | Seguidor aplica estado truncado | Instância aguarda snapshot íntegro |
| **V34** | ASN.1 DER Buffer Overflow Fuzzing | Compliance | Servidor crasha ao decodificar | Retorno HTTP 400/422 controlado |
| **V35** | Injeção de Timestamp Forjado | Imutabilidade | Evento antigo registrado no ledger | Validador temporal recusa registro |
| **V36** | Adulteração em Merkle Folha Ímpar | Imutabilidade | Root hash não se altera | Divergência imediata de Root Hash |
| **V37** | Length Extension Attack no WAL | Storage | Sufixo aceito sem novo commit | Falha na validação de hash em cadeia |
| **V38** | Protobuf Framing Corrompido gRPC | Rede | Servidor Core crasha na porta 17474 | Descarte seguro de pacote malformado |
| **V39** | Slow Streaming OTLP Ingestion | Telemetria | Travamento de workers de telemetria | Timeout e liberação de thread |
| **V40** | Query Limit Exceeded Amplification | Telemetria | Resposta aloca memória ilimitada | Aplicação de cap estrito de registros |

---

## 4. Pipeline de Execução e Qualificação Contínua

Para integrar a matriz completa ao fluxo perpétuo do repositório:

```bash
# 1. Subir o mock upstream seguro em background
python3 stub_upstream.py --port 19000 &

# 2. Executar a suíte de regressão comportamental dos oráculos
python3 -m unittest discover -s tests -v

# 3. Executar o SuperRunner v4 com perfil destrutivo e validação de storage
python3 runner_v4.py --profile destructive --host 127.0.0.1 --port 7475

# 4. Iniciar o runner adversarial contínuo 24/7
python3 perpetual_runner.py --profile full --delay 2.0 --max-reports 100

```

Todas as evidências colhidas são consolidadas em `reports/`, gerando digests SHA-256 canônicos e persistindo metadados no log de evidências HRKL do HeraclitusDB sem gerar efeitos colaterais fora do ambiente local de loopback.