# Changelog

Todas as mudanças notáveis deste projeto são documentadas aqui.

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o
projeto adota [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado
- **Bloco `coverage` no `-f json`: `checks_skipped` e `truncations`.** Antes, uma
  checagem que rodou e não achou nada, uma checagem que nem fazia sentido rodar
  (TLS num alvo que só fala texto aberto) e uma resposta HTTP lida pela metade
  convergiam no mesmo silêncio do relatório. `TlsChecker` agora declara
  explicitamente quando não há endpoint TLS para avaliar, em vez de devolver zero
  achados; `HttpClient` registra toda resposta truncada pelo teto de corpo. As
  duas listas aparecem sempre no JSON, mesmo vazias.

## [0.5.0] — 2026-08-14

### Segurança
- **Bomba de descompressão contida.** O teto `max_body_bytes` era aplicado *depois* da
  descompressão feita pelo `httpx`: uma bomba de 64 MiB de zeros (~64 KB na rede) levava o
  pico de alocação a **141,6 MiB** com o teto configurado em 4 KB. O relatório saía do
  tamanho certo — o teto protegia o texto, nunca a memória, que é o recurso que a bomba
  quer consumir. A descompressão passou a ser da própria ferramenta (`iter_raw()` + `zlib`
  incremental com `max_length`), o que limita a expansão na origem: pico medido depois,
  **2,7 MiB**. Junto vieram um teto de bytes *na rede* (um fluxo de blocos vazios
  descomprime para zero byte e nunca cruzaria o teto de saída) e `Accept-Encoding:
  gzip, deflate` declarado explicitamente — pedir `br`/`zstd` devolveria a descompressão a
  um codec sem teto. Corpo em codec desconhecido sai **vazio e marcado como incompleto**,
  nunca como texto inventado.
- **Guarda anti-SSRF fecha CGNAT e IPv4 mapeado em IPv6.** `100.64.0.0/10` (RFC 6598) não é
  "privado" para o módulo `ipaddress` e passava — e dentro dessa faixa está
  `100.100.100.100`, endpoint de metadados da Alibaba Cloud. `::ffff:100.64.0.1` também
  passava, porque a checagem lia a forma IPv6 sem desembrulhar o IPv4 embutido. A
  normalização passou a ser nossa: a resposta do stdlib para IPv4 mapeado mudou entre patch
  releases do Python (CVE-2024-4032) e o projeto suporta 3.10+. `192.0.0.0/24` e
  `198.18.0.0/15` ficaram explícitas pelo mesmo motivo.
- **`--autorizado` deixa de ser oculto.** A trava ética estava com `hidden=True`: segurança
  por obscuridade justamente no controle que decide se a ferramenta envia tráfego que o
  alvo registra. O texto de ajuda agora diz o que a opção habilita e o que ela declara
  (autorização por escrito, com escopo). O aviso em tempo de execução continua.

### Adicionado
- **Selo de proveniência em todos os formatos** (auditoria cruzada 2026-08-05): `commit` +
  `ruleset_hash` passam a aparecer também no **HTML/Markdown** (cabeçalho/rodapé) e no
  **SARIF** (`run.properties.ruleset_hash` + `run.versionControlProvenance`), não só no
  JSON — o entregável humano e o que sobe pro Code Scanning também ficam vinculáveis. Com
  teste de regressão que falha se um refactor futuro dropar o selo de qualquer formato.
- **Testes property-based (Hypothesis)** da defesa anti-SSRF: geram milhares de endereços e
  afirmam as invariantes que fixam a classe do bypass — toda faixa reservada/CGNAT é
  bloqueada e `::ffff:X` decide igual a `X`.
- **Proveniência no envelope do relatório JSON**: `commit` (SHA de 40 hex do código que
  rodou), `ruleset_hash` (sha256 do catálogo — ids, escala de severidade e taxonomia) e
  `artifact_sha256` (sha256 do próprio documento, calculado sobre ele *sem* esse campo,
  com a receita de verificação publicada no código). Sem eles, comparar dois laudos do
  mesmo alvo era ambíguo: "quatro achados sumiram" tanto podia ser correção quanto mudança
  de regra. Fora de um repositório git — instalação por wheel, por exemplo — `commit` sai
  `null`: a varredura nunca falha por causa do carimbo, e "não sei" é resposta honesta.
  A descoberta segue a ordem `SENTINELA_COMMIT` → `git rev-parse HEAD` → `null`.
- **Imagem base do Dockerfile fixada por digest** (índice multi-arquitetura), no lugar da
  tag móvel `python:3.12-slim`. O repositório prega SHA-pinning e a Esteira o cobra de
  quem audita; a própria imagem flutuava, e dois `docker build` do mesmo commit montavam
  ambientes diferentes. Os dois estágios usam o mesmo digest, com teste guardando isso.
- **Checagem de superfície de formulários e injeção** (`forms`, não-intrusiva): análise passiva
  do HTML já baixado, sem enviar payload. Detecta credencial trafegando em GET (`SENHA_EM_GET`,
  A07/CWE-598), formulário com campo sensível postando para destino `http://` — conteúdo misto —
  (`FORMULARIO_CREDENCIAL_SEM_HTTPS`, A04/CWE-319, sem duplicar o `SENHA_SEM_HTTPS` do checker de
  conteúdo), formulário que muda estado sem token anti-CSRF (`CSRF_TOKEN_AUSENTE`, A01/CWE-352),
  parâmetro refletido sem escape como superfície de XSS (`REFLEXAO_DE_PARAMETRO`, A05/CWE-79) e
  dado sensível na query string (`DADO_SENSIVEL_NA_URL`, A07/CWE-598). É honesta sobre a fronteira:
  sinaliza a *superfície*; a CONFIRMAÇÃO ativa (provar SQLi/XSS com payload) é da edição Pro.
  A extração de formulários é feita por **regex de escaneamento limitado** (teto por tag, O(n)) —
  não pelo `HTMLParser` da stdlib, que é super-linear num `<script` sem fechamento e travava a
  varredura num corpo hostil de 256 KB (mesma classe de DoS que o F100 matou em `content.py`;
  descoberto por bateria de campo, coberto por teste que cronometra a regressão).

### ⚠️ Mudanças incompatíveis
- **Contrato do relatório JSON** (`-f json`): as chaves passam para inglês, seguindo o schema
  comum da suíte, e o documento traz `"schema": "suite-appsec/1"` no topo. A regra (já escrita
  em `core/models.py`) é: identificador em inglês, texto para humano em PT-BR — o relatório JSON
  era o único lugar que a desrespeitava. De-para: `ferramenta`→`tool`, `versao`→`version`,
  `alvo`→`target`, `modo`→`mode`, `achados`→`findings`, `erros`→`errors`,
  `contagem_por_severidade`→`summary.by_severity`, `nota`→`summary.score`
  (`valor`→`value`, `conceito`→`grade`, `resumo`→`text`). Em cada achado:
  `titulo`→`title`, `severidade`→`severity` (agora identificador em inglês minúsculo:
  `medium`; o rótulo PT-BR continua em `severity_label`), `descricao`→`description`,
  `evidencia`→`evidence`, `impacto`→`impact`, `recomendacao`→`recommendation`,
  `referencias`→`references`. `by_severity` traz sempre as 5 chaves, inclusive zeradas.
  Novos campos: `owasp_edition`, `severity_rank`, `subject`, `cwe_name`.
- **`--falhar-em alta` (padrão) agora falha em alvo servido por HTTP puro**, por causa do
  novo achado `SEM_HTTPS` (severidade alta). Quem roda a Sentinela em pipeline contra
  *staging* interno em texto aberto verá o build quebrar — é o sinal correto, mas é uma
  quebra. Saídas explícitas: `--falhar-em critica` ou `--pular transport`.
- **`--somente`/`--pular` com ID inexistente agora sai com código 2** em vez de rodar zero
  checagens e imprimir "Nota 100/100 · A" com código 0. Um pipeline que dependia desse
  comportamento estava silenciosamente sem gate.
- **`partialFingerprints` do SARIF mudou de valor** (passou do rule id para um hash da
  instância). Alertas já abertos na aba *Security* do GitHub serão reabertos uma vez. O
  namespace da chave (`sentinelaFindingId/v1`) foi mantido de propósito.
- O subcomando `checagens` foi renomeado para `regras` (nome comum da suíte). `checagens`
  continua funcionando como alias.

### Adicionado
- **Políticas declaradas via `<meta>` no HTML** passam a ser reconhecidas: hospedagem estática
  (GitHub Pages, S3, Cloud Storage) não emite cabeçalho e usa
  `<meta http-equiv="Content-Security-Policy">` / `<meta name="referrer">`. Antes, TODO site
  desse tipo recebia `CSP_AUSENTE` e `REFERRER_POLICY_AUSENTE` como falso positivo. O novo
  achado informativo `POLITICA_VIA_META` registra a diferença — e `CLICKJACKING_SEM_PROTECAO`
  **continua** sendo emitido, porque numa CSP entregue por `<meta>` o navegador IGNORA
  `frame-ancestors`, `sandbox` e `report-uri`.
- Achado `SEM_HTTPS` (alta): alvo servido em texto aberto. Antes, um site 100% em HTTP com
  cabeçalhos impecáveis tirava **92/100 conceito A** — o pior veredito que a ferramenta podia
  entregar a um cliente pagante.
- Achado `COOKIE_CSRF_LEGIVEL_POR_JS` (informativo) para o padrão *double-submit*.
- `--version`/`-V` no comando principal (o subcomando `versao` continua existindo).
- `--falhar-em` aceita o vocabulário em inglês (`none|info|low|medium|high|critical`) além do
  português, e passa a incluir o nível `info`.
- `sentinela regras` lista também o catálogo completo de achados com OWASP 2025/CWE.
- Campo `subject` no achado (o ativo específico: o subdomínio), usado para dar identidade de
  instância no SARIF e localizar o alerta no host certo.
- **Descoberta de superfície de ataque** (`--descobrir`): enumeração de subdomínios via
  **Certificate Transparency** (Cert Spotter como fonte primária, crt.sh como *fallback*) e
  detecção de **subdomain takeover** — CNAME órfão apontando para serviço não reivindicado
  (S3, GitHub Pages, Heroku, Azure e outros), confirmado por NXDOMAIN ou assinatura no corpo.
- Checagem de **conteúdo da página** (`content`): conteúdo misto (*mixed content*), ausência
  de **Subresource Integrity (SRI)** em recursos de terceiros, formulário com `action`
  insegura, campo de senha servido sem HTTPS e página sensível sem `Cache-Control: no-store`.
- Checagem de **arquivos públicos** (`well-known`): leitura de `robots.txt` (RFC 9309) para
  sinalizar caminhos sensíveis expostos por convenção.
- **Análise profunda de CSP** (estilo CSP Evaluator): curinga em `script-src`, ausência de
  `object-src 'none'` e de `base-uri`, e política apenas em `report-only`.
- **Endurecimento de TLS**: sinalização de ausência de TLS 1.3 e de cifras sem
  Perfect Forward Secrecy, além do sondador de protocolo legado (TLS 1.0/1.1).
- Cookies: `SameSite=None` inseguro e validação dos prefixos `__Host-`/`__Secure-`.
- DNS/e-mail: checagem de **MTA-STS** e **TLS-RPT** (quando há registro MX).
- Execução paralela do motor e das sondas (pré-coleta, checagens e handshakes de TLS) e
  seção "Plano de ação — comece por aqui" no relatório.
- Exportação **SARIF 2.1.0** (`-f sarif`): formato *machine-readable* padrão, com
  `security-severity` e taxonomia OWASP/CWE por achado; ingestável por pipelines e pela aba
  *Security* do GitHub (cada achado é localizado pela URL do alvo).

### Corrigido
- **Falso positivo conceitual na CSP:** a política que o Google recomenda em
  `csp.withgoogle.com/docs/strict-csp` era penalizada em 11 pontos. Na presença de
  `'strict-dynamic'` (ou de nonce/hash) o navegador IGNORA a allowlist de host, os esquemas
  e o `'unsafe-inline'` — são tokens de compatibilidade, não falhas. A ferramenta estava
  recomendando ENFRAQUECER uma configuração correta. `'unsafe-eval'` continua sendo achado
  (`strict-dynamic` não o neutraliza) e `'unsafe-inline'` em `style-src` também.
- **Falso positivo em cookie de CSRF:** `XSRF-TOKEN` (Laravel/Angular/Axios), `csrftoken`
  (Django) e `_csrf` (csurf) saíam como MÉDIA com o impacto "um XSS rouba a sessão" — duas
  afirmações falsas. No padrão *double-submit* o JavaScript PRECISA ler esse cookie, e marcá-lo
  `HttpOnly` quebra a aplicação. Passa a ser informativo. `Secure` e `SameSite` nesse cookie
  continuam com achado próprio, com a severidade de sempre.
- **Escopo da varredura em hospedagem gerenciada:** o domínio registrável passa a considerar a
  seção privada da Public Suffix List. Antes, `paulo.github.io` virava `github.io`,
  `cliente.blogspot.com` virava `blogspot.com` e `empresa.br.com` virava `br.com` — a ferramenta
  auditava o DNS do PROVEDOR e atribuía o achado ao cliente errado. Com `--descobrir` era pior:
  consultava o Certificate Transparency e fazia requisições HTTP contra o namespace de terceiros.
  O checker de takeover ganhou barreira de escopo explícita (nunca sobe acima do alvo autorizado).
- **Conceito da nota tetado pela gravidade:** um `.env` de produção publicado lia "conceito C"
  (100 − 40 = 60). O VALOR continua sendo exatamente `100 − soma dos pesos`, reconstruível à
  mão; só o CONCEITO reprova — achado crítico → F, achado alto → no máximo D. O resumo explica
  a divergência entre número e letra quando o teto atua.
- **Injeção de markup pelo alvo no relatório de terminal:** nome de cookie estilo array
  (`cart[items]`, comum em PHP/Rails) era impresso como `cart` — evidência FACTUALMENTE ERRADA,
  em silêncio; um `Server: [/]` de 5 bytes derrubava o relatório com `MarkupError` depois da
  varredura inteira; e o alvo conseguia escrever texto colorido e link clicável no terminal do
  consultor. No Markdown, uma evidência com crase escapava do *code span* e virava HTML ao ser
  renderizada por terceiro — corrigido pela regra de cerca do CommonMark, **sem alterar um byte**
  da evidência.
- **Custo de CPU contra alvo hostil:** uma página de 256 KB (o teto exato que o motor entrega)
  sem nenhum `>` fazia os regex de tag degradarem para O(n²) — 82,3 s de CPU medidos, com ZERO
  achados. Com o teto de 2048 caracteres por tag: 1,3 s, sem perder nenhum caso de HTML legítimo
  (inclusive `<` dentro de valor de atributo).
- **Sonda de transporte contaminada:** para um alvo em porta não-padrão (`http://host:8123/`),
  a sonda ia sempre na porta 80 — o veredito de transporte do app era decidido por um serviço
  DIFERENTE no mesmo host. Para alvo `https://`, a sonda continua na 80 de propósito.
- **SARIF:** N instâncias distintas do mesmo achado colapsavam em um alerta só (o
  `partialFingerprints` carregava apenas o rule id) e o catálogo de regras carregava o hostname
  de UMA vítima no `name`. O `evidence` e o `impact` agora chegam ao SARIF, e um achado por host
  é localizado no próprio host.
- Guarda anti-SSRF: destino de redirecionamento cujo nome não resolve passa a falhar
  **fechado** (antes falhava aberto, deixando uma janela de DNS rebinding).
- Nota de higiene com teto em **F** quando o certificado está quebrado ou o alvo é inalcançável.
- DNS distingue "consulta falhou" (inconclusivo) de "ausência real", evitando falso-positivo
  de SPF/DMARC sob resolver instável.
- Instruções de instalação: `pip install sentinela-scan` não funcionava (o pacote não existe no
  PyPI) e `pip install sentinela` instalaria um projeto de terceiro. A receita correta —
  `pipx`/`pip install "git+https://github.com/Paulo-Marcos-Lucio/sentinela.git"` — está no README,
  no guia de uso e na receita de CI.
- README: `--timeout` é 8s (dizia 15s), o `sarif` aparece no diagrama de arquitetura e as opções
  `--descobrir` e `--sem-verificacao-tls` estão documentadas. Passa a documentar o checker `forms`
  (superfície de injeção passiva, mapeada a A01/A04/A05/A07 + CWE), a fronteira explícita
  passivo↔ativo e os números de campo medidos (superfície P/R 0,909, `SENHA_EM_GET` 1,00; confirmação
  ativa da edição Pro com precisão/recall 1,00 nas 7 classes contra laboratório controlado), com o
  recado de que a camada ativa é *gated* (`--autorizado` + escopo).
- CHANGELOG: `--perfil` estava listado ao mesmo tempo em "Corrigido" e em "Planejado".

### Interno
- Um handshake TLS a menos por alvo (5 → 4): `_fetch_certificate` e `_tls_capabilities`
  montavam o mesmo `SSLContext` byte a byte e liam campos diferentes do mesmo socket.
- Deduplicação: `is_ip` (×3), o extrator da PSL + `registrable` (×2) e o truncador (×2) viram
  `checks/_util.py`; 4 constantes de referência nunca usadas e a dependência de dev `respx`
  (0 usos) foram removidas.
- Testes: 162 → 297. Passa a existir teste ponta-a-ponta da CLI (motor real, rede falsa,
  arquivo em disco, código de saída), teste do `HttpClient` real contra servidor local
  (guarda anti-SSRF e teto de corpo eram as únicas linhas do módulo sem nenhuma execução) e
  meta-testes que exigem taxonomia, explicação didática e ao menos um caso positivo para todo
  achado do catálogo. Cobertura 88% → 93%, com portão `--cov-fail-under=90` no `pyproject.toml`.
- O teste `test_scan_runs_checks_in_parallel_and_completes` batia na INTERNET (2 conexões a
  `example.com` por execução, em cada versão de Python do CI) e sua única asserção era
  verdadeira mesmo sem rede alguma. Agora é offline e afirma o que o nome promete.
- Actions do CI fixadas por SHA (a tag `@v4` é um ponteiro móvel) + `.github/dependabot.yml`
  mensal — pinar sem atualizar congela a versão vulnerável.
- Versão com fonte única: `pyproject.toml` passa a lê-la de `src/sentinela/version.py`.

### Planejado
- Detecção de bibliotecas front-end desatualizadas (A03 Supply Chain)

## [0.1.0] — 2026-07-21

### Adicionado
- Motor de varredura não-intrusivo com arquitetura de checagens plugáveis.
- Checagens: cabeçalhos de segurança, TLS/certificado, redirecionamento HTTP→HTTPS,
  cookies, CORS, métodos HTTP, exposição de informação e DNS/e-mail (SPF/DMARC/CAA/DNSSEC).
- Checagem intrusiva de rotas sensíveis (`.git`, `.env`, etc.), gated por `--autorizado`.
- Taxonomia OWASP Top 10:2025 + CWE por achado.
- Nota de higiene (0–100) com conceito A–F.
- Relatórios em terminal (rich), Markdown, HTML autocontido e JSON.
- CLI `sentinela` com `scan`, `checagens` e `versao`; código de saída para CI (`--falhar-em`).
- Suíte de testes offline, CI (ruff + mypy strict + pytest 3.10–3.12) e imagem Docker.
- Perfis de varredura (`--perfil completo|rapido`): o modo `rapido` pula as checagens de rede
  extra (TLS, DNS/e-mail e robots.txt) para uma triagem ágil.

[Não lançado]: https://github.com/Paulo-Marcos-Lucio/sentinela/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Paulo-Marcos-Lucio/sentinela/compare/v0.1.0...v0.5.0
[0.1.0]: https://github.com/Paulo-Marcos-Lucio/sentinela/releases/tag/v0.1.0
