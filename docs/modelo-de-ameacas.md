# Modelo de ameaças da suíte — o scanner como alvo

Todo documento da Sentinela até aqui descreve a ferramenta apontada para **fora**:
o que ela verifica no alvo que o operador escolheu. Este documento inverte a
pergunta. A suíte AppSec ([Sentinela](https://github.com/Paulo-Marcos-Lucio/sentinela),
[Guardião](https://github.com/Paulo-Marcos-Lucio/guardiao),
[Chaveiro](https://github.com/Paulo-Marcos-Lucio/chaveiro),
[Esteira](https://github.com/Paulo-Marcos-Lucio/esteira) e o
[Laboratório OWASP](https://github.com/Paulo-Marcos-Lucio/laboratorio-owasp))
processa entrada que não controla — resposta HTTP de um servidor arbitrário,
token de terceiro, log de CI, commit de outro autor. Cada uma dessas entradas é
uma superfície de ataque contra o próprio scanner, e o modelo de ameaça correto
é literalmente **"o alvo pode não querer ser auditado"**: um servidor hostil,
comprometido ou apenas mal configurado pode tentar transformar a varredura em
negação de serviço, em vazamento de rede interna ou em relatório enganoso — sem
nunca precisar quebrar autenticação nenhuma, porque o scanner fala com ele
por definição.

Este documento cobre a parte da suíte que fala HTTP com um alvo escolhido pelo
operador — hoje, a Sentinela. Guardião, Chaveiro e Esteira leem arquivo local,
histórico de Git e log de CI: a superfície de "servidor hostil na rede" não se
aplica a eles do mesmo jeito, e cada um documenta o que trata como hostil no
próprio README (ex.: o Chaveiro decodifica token sem verificar assinatura, de
propósito, e nunca executa o que decodifica).

## Ator e vetor

**Ator:** o dono (ou quem comprometeu) o alvo apontado pelo operador — o único
participante que controla o que a resposta HTTP contém.

**Vetor:** a própria resposta que o operador pediu para ser lida: cabeçalhos,
corpo, redirecionamentos, codificação de transporte. O scanner não pode se
recusar a olhar — ler a resposta é o produto. A pergunta que importa é *quanto*
custa olhar uma resposta adversarial, e é isso que as defesas abaixo limitam.

## Defesas confirmadas

Cada item abaixo tem teste que cronometra ou mede a regressão — a defesa não é
uma alegação, é uma propriedade que o CI reprova se for desfeita.

### Bomba de descompressão

Um servidor pode anunciar `Content-Encoding: gzip` e devolver poucos KB na rede
que se expandem para dezenas ou centenas de MiB — o objetivo é estourar a
memória do processo que descomprime, não a banda.

A Sentinela assume a descompressão para poder limitá-la (`core/http.py`,
`_Descompressor`): em vez de deixar o `httpx` descomprimir o corpo inteiro antes
de qualquer checagem de teto, ela descomprime **incrementalmente**, pedaço de
rede por pedaço de rede, com `zlib.decompressobj().decompress(bruto, teto)` — o
segundo argumento é o teto de saída daquele pedaço, então a materialização
nunca ultrapassa o que ainda cabe no orçamento (`core/http.py:321`,
`max_body_bytes`). Dois tetos independentes fecham o problema: o de saída
(bytes descomprimidos, o que o operador pediu) e o de rede (`_TETO_BYTES_NA_REDE`,
2 MiB) — sem o segundo, um fluxo que expande pouco manteria a leitura andando
indefinidamente sem nunca cruzar o teto de saída.

Teste (`tests/test_http_client.py::test_gzip_bomb_respeita_teto_de_memoria`):
uma bomba sintética de 64 MiB de zeros comprimidos em ~64 KB na rede é baixada
com `max_body_bytes=4096`; o teste mede o pico real de RSS do processo durante
a leitura e reprova se passar de 8 MiB — quase 8× o teto pedido, folga para o
ruído do runtime, mas duas ordens de grandeza abaixo do que a bomba expandiria
sem o teto incremental.

### ReDoS / degradação superlinear em HTML hostil

Duas checagens (`checks/content.py` e `checks/forms.py`) extraem informação do
HTML com regex, e regex mal desenhada sobre entrada hostil é uma classe clássica
de DoS: um padrão como `[^>]*?` sobre uma tag `<script ` de centenas de KB sem
nenhum `>` que a feche degrada para O(n²) — medido em produção antes da correção
(F100, ver `CHANGELOG.md`): 256 KB desse padrão custavam **~84 s de CPU e zero
achados**, e a versão anterior de `forms.py`, que usava o `HTMLParser` da
stdlib para o mesmo tipo de entrada, passava de **120 s**. O operador não via
erro — via a varredura travar.

A correção não foi ajustar o regex, foi mudar a classe de algoritmo: toda
extração de tag agora tem um teto explícito de bytes escaneados por tag
(`_ATTR_SCAN = 2048`, igual nos dois arquivos), o que torna a busca **linear**
no tamanho do corpo — nenhum `<...>` gigante sem fechamento degrada a
varredura, porque nenhuma busca olha além do teto por tag. HTML legítimo não é
afetado: 2 KB de atributos antes do atributo procurado não ocorre em página
real.

Testes que cronometram a regressão, não só o resultado:

- `tests/test_content.py::test_corpo_hostil_de_256kb_nao_estoura_o_orcamento_de_cpu`
  — corpo de exatamente `_PRIMARY_BODY_CAP` (o teto que o motor garante
  entregar) todo em `<script `, sem achados, e reprova se passar de 3 s.
- `tests/test_forms.py::test_corpo_hostil_nao_trava_a_varredura` — `<script` +
  256 KB sem fechamento, reprova se passar de 1 s.
- `tests/test_forms.py::test_corpo_hostil_com_form_valido_ainda_e_lido_rapido`
  — o mesmo ruído hostil **antes** de um formulário legítimo, provando que o
  teto não sacrifica o achado real por trás do lixo.

### SSRF via redirecionamento

O alvo pode responder com um `Location` que aponta para `127.0.0.1`,
`169.254.169.254` (metadado de nuvem), uma faixa `10.0.0.0/8` ou qualquer outro
endereço não roteável — tentando usar o scanner, que roda dentro da rede do
operador ou de um runner de CI, como proxy para alcançar infraestrutura
interna.

Os redirecionamentos são seguidos **manualmente** (`follow_redirects=False` no
cliente `httpx` de base, loop próprio em `request()`), e cada salto é validado
contra `_host_is_blocked()` antes de a requisição seguinte sair: IP literal ou
resolvido caindo em privado, loopback, link-local, CGNAT (`100.64.0.0/10`,
faixa que o `is_private` da stdlib não cobre) ou IPv4 mapeado em IPv6 é
bloqueado. A política de falha na resolução é **fechada**: se o nome não
resolve, o salto não é seguido — falhar aberto abriria exatamente a janela de
corrida em que vive o DNS rebinding (`core/http.py:441-452`).

A guarda tem uma isenção deliberada e só uma: o **alvo inicial**, escolhido
explicitamente pelo operador, nunca é bloqueado — é assim que a ferramenta
audita infraestrutura interna/staging de propósito. Um upgrade de esquema
(`http://` → `https://`) na mesma porta ou no par padrão 80→443 também passa,
porque é o comportamento normal de qualquer servidor bem configurado; qualquer
outra troca de porta no redirect é tratada como pivô e cai na guarda.

Testes em `tests/test_http_client.py`: `test_redirecionamento_para_host_interno_nunca_e_requisitado`,
`test_o_alvo_inicial_escolhido_pelo_operador_nunca_e_bloqueado`,
`test_cgnat_e_bloqueado`, `test_ipv4_mapeado_em_ipv6_e_bloqueado`,
`test_faixas_especiais_de_teste_e_ietf_sao_bloqueadas`,
`test_host_que_nao_resolve_falha_fechado`.

### Corpo ilimitado

Independente de compressão, um alvo pode simplesmente nunca fechar a conexão e
transmitir sem parar. O download é feito por streaming (`response.iter_raw()`)
e interrompido assim que `max_body_bytes` de saída **ou** o teto de rede é
cruzado — o corpo nunca é lido inteiro antes de aplicar o teto, então o
consumo de memória do processo é limitado pelo teto, não pelo tamanho da
resposta. Uma leitura parcial é marcada `truncado=True` (nunca vira "ausência"
silenciosa) — a mesma bandeira cobre teto batido, conexão caída no meio, ou um
codec de compressão que a ferramenta declaradamente não sabe desembrulhar
(ver gap abaixo).

### Isolamento de falha por checagem

Uma resposta desenhada para explorar um bug específico de UMA checagem (uma
exceção não tratada, por exemplo) não pode derrubar a varredura inteira: o
motor (`core/engine.py`) captura e registra a falha de cada checagem
individualmente. O pior caso de um bug isolado é perder aquele achado, não
perder o relatório todo.

## Gaps declarados

Documentar o que **não** está fechado é a mesma disciplina de honestidade que
rege severidade e cobertura no resto da suíte — inflar a superfície de defesa
tem o mesmo custo de confiança que inflar um achado.

- **Janela de TOCTOU no DNS rebinding.** A guarda anti-SSRF resolve o host do
  próximo salto e decide **antes** de mandar a requisição seguinte
  (`_host_is_blocked`), mas quem de fato conecta depois é o `httpx`, que
  resolve o nome de novo por conta própria. Falhar fechado quando a nossa
  resolução não bate reduz a janela de corrida entre as duas resoluções — não
  a elimina. Fechar de vez exigiria fixar o IP resolvido e forçar o `httpx` a
  conectar nele (pinning de conexão), o que hoje não é feito.

- **O alvo inicial nunca passa pela guarda.** É uma escolha deliberada — sem
  ela a ferramenta não poderia auditar infraestrutura interna, seu caso de uso
  central em ambiente de staging/VPS — mas é, por definição, uma superfície
  que fica de fora: se o operador (ou uma automação mal configurada em nome
  dele) aponta a varredura para um alvo interno por engano, nada na Sentinela
  impede.

- **Sem teto de duração total no download.** O cliente `httpx` tem timeout de
  15 s (`core/http.py`, `timeout: float = 15.0`), mas esse timeout é por
  operação de rede (cada leitura de `iter_raw()`), não uma janela agregada
  para o download inteiro. Um alvo que entrega bytes em pedaços pequenos,
  cada um chegando pouco antes do timeout de leitura estourar, pode manter uma
  varredura presa por muito mais que 15 s sem que nenhum teto de bytes seja
  cruzado. Ao contrário da bomba de descompressão e do ReDoS acima, este ponto
  **não tem teste cronometrado** — é uma leitura do código, não uma defesa
  verificada.

- **Codec de compressão não suportado vira corpo vazio, não corpo real.** O
  `Accept-Encoding` só pede `gzip, deflate` — de propósito, para não fazer o
  comportamento da ferramenta depender de qual pacote opcional (`brotli`,
  `zstd`) está instalado na máquina que roda o scan. Um servidor que só
  responde em `br`/`zstd` faz a checagem de conteúdo trabalhar sobre corpo
  vazio (marcado `truncado=True`, nunca inventado) em vez do HTML real — não é
  uma falha de segurança do scanner, mas é perda de cobertura que um operador
  pode não esperar.

- **Confirmação ativa de injeção não existe na edição pública.** Não é uma
  lacuna de robustez do scanner contra alvo hostil — é a fronteira Pro,
  documentada no README principal — mas pertence aqui porque delimita o que
  este modelo de ameaça cobre: tudo acima protege a ferramenta *ao ler* um
  alvo hostil; nenhuma checagem pública *envia* payload, então não há, na
  edição pública, uma superfície equivalente de "resposta do alvo a um ataque
  ativo" para modelar.

## Como isto se sustenta

Nenhuma das defesas confirmadas depende de o operador lembrar de uma flag: são
o comportamento padrão do cliente HTTP e das checagens de conteúdo, cobertas
por teste que falha se a defesa regredir — não por revisão manual do próximo
PR. Os gaps declarados, por outro lado, são exatamente o que ficaria invisível
numa lista só de defesas: o valor deste documento está tanto na primeira
metade quanto na segunda.
