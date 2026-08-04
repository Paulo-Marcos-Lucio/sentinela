# Reprodutibilidade: o mesmo alvo, o mesmo veredito, em qualquer máquina

Um laudo de segurança que muda de máquina para máquina não é laudo. Este documento
registra o que a Sentinela garante, o que ela **não** garante, e como ela avisa quando
não conseguiu verificar algo.

## A regra central: inconclusivo não é ausência

Um scanner tem três respostas possíveis, não duas:

| Resposta | Significado | Peso na nota |
| --- | --- | --- |
| **Achado** | Verifiquei e o problema existe | conforme a severidade |
| **Silêncio** | Verifiquei e está em ordem | zero |
| **Não avaliado** | **Não consegui verificar** | zero, e aparece no relatório |

A terceira não existia. Tudo que falhava virava silêncio — e silêncio, dentro de um
laudo, lê como aprovação. Era daí que vinha a divergência entre máquinas: uma rede pior,
um resolvedor filtrado ou um OpenSSL mais novo apagavam achados sem deixar rastro.

Os achados de limite declarado hoje são:

| ID | Quando aparece |
| --- | --- |
| `CSP_NAO_AVALIADA` | o HTML veio truncado e a metatag de CSP podia estar no pedaço que não chegou |
| `DNS_NAO_AVALIADO` | o resolvedor desta máquina não respondeu ao básico do domínio |
| `TRANSPORTE_NAO_AVALIADO` | não foi possível alcançar a porta 80 (firewall de egresso, portal cativo) |
| `TLS_LEGADO_NAO_AVALIADO` | o OpenSSL local não permite oferecer TLS 1.0/1.1 |
| `DESCOBERTA_NAO_AVALIADA` | as fontes de Certificate Transparency não responderam |
| `RELOGIO_LOCAL_DIVERGENTE` | o relógio da máquina está longe do `Date` do alvo |

Todos são informativos e **não** tiram ponto: declarar um limite não pode punir o alvo.

## O que é determinístico

Verificado empiricamente: duas execuções contra o mesmo alvo produzem relatórios
**byte a byte idênticos**, com exceção dos carimbos de tempo. Isso vale inclusive com
cache de DNS frio contra quente (medido: 4,78 s contra 0,33 s na mesma máquina, zero
achados diferentes).

Sustentam isso:

- toda saída passa por `sorted()`; nenhum `set` define ordem de relatório;
- `pool.map` preserva a ordem de entrada, e não há paralelismo derivado de `os.cpu_count()`;
- nenhum uso de `random`;
- `tldextract` roda com `suffix_list_urls=()` — a lista de sufixos vem com o pacote, sem
  download e sem diferença entre cache frio e quente;
- a validação de cadeia TLS usa o bundle do `certifi` (o mesmo do cliente HTTP), e não a
  loja de CAs do sistema operacional, que varia por distribuição e por CA corporativa;
- o cliente HTTP roda com `trust_env=False`: `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` e
  `SSL_CERT_FILE` do ambiente **não** entram na varredura;
- todas as dependências têm piso **e** teto em `pyproject.toml`.

## O que continua dependendo da máquina — e como o relatório avisa

| Variável | Efeito | Como aparece |
| --- | --- | --- |
| Versão do OpenSSL | decide se dá para testar TLS 1.0/1.1 | `TLS_LEGADO_NAO_AVALIADO` + carimbo no cabeçalho |
| Resolvedor de DNS | decide se as checagens de DNS/e-mail rodam | `DNS_NAO_AVALIADO` + nameservers no cabeçalho |
| Relógio | decide a validade do certificado | `RELOGIO_LOCAL_DIVERGENTE` |
| Rede (latência, egresso) | corpo truncado, porta 80 inalcançável | `CSP_NAO_AVALIADA`, `TRANSPORTE_NAO_AVALIADO` |
| Geografia (CDN) | o alvo pode responder cabeçalhos diferentes por região de borda | fora do alcance da ferramenta — anote a região se for relevante |

Todo relatório carrega agora as condições de execução (sistema, Python, OpenSSL,
resolvedor, relógio) no cabeçalho, em Markdown, HTML e JSON. Diante de dois relatórios
divergentes do mesmo alvo, é por aí que se descobre qual dos dois vale.

## A que código e a que regras o laudo se prende

Saber que a máquina era a mesma não basta: é preciso saber que a **ferramenta** era a
mesma. `version: "0.1.0"` não serve para isso — esse nome já designou dezenas de árvores
diferentes. O envelope do JSON carrega três selos:

| Campo | Responde | Como é obtido |
| --- | --- | --- |
| `commit` | qual **código** rodou | `SENTINELA_COMMIT` → `git rev-parse HEAD` no diretório do pacote → `null` |
| `ruleset_hash` | qual **catálogo** rodou (ids, escala de severidade, taxonomia) | sha256 do catálogo montado em ordem canônica |
| `artifact_sha256` | qual **documento** foi entregue | sha256 do próprio laudo, calculado sobre ele *sem* esse campo |

Sem os dois primeiros, "no reteste quatro achados sumiram" é ambíguo: sumiram porque o
alvo foi corrigido, ou porque a regra mudou entre as execuções? `ruleset_hash` **não**
cobre a lógica de detecção, de propósito — refinar um detector não muda o catálogo. Para
isso existe o `commit`; os dois juntos respondem à pergunta, e nenhum dos dois sozinho.

Fora de um repositório git (instalação por wheel, por exemplo), `commit` sai `null`. A
varredura nunca falha por causa do carimbo: "não sei" é resposta honesta, laudo que não
sai não é.

Conferindo o selo do documento, sem a ferramenta:

```python
import hashlib, json

doc = json.load(open("laudo.json", encoding="utf-8"))
selo = doc.pop("artifact_sha256")
calc = hashlib.sha256(json.dumps(doc, ensure_ascii=False, indent=2).encode("utf-8")).hexdigest()
assert calc == selo
```

O selo prova **não-adulteração do arquivo**, não autenticidade da origem: quem reescrever
o laudo inteiro recalcula o hash junto. Autenticidade é assinatura, e é outro trabalho.

## Edições: não existe build que ligue varredura ativa sozinha

Não há mais `edition.py`. A varredura ativa depende **sempre** de declaração explícita:

```bash
sentinela scan alvo.com                          # não-intrusivo, o padrão
sentinela scan alvo.com --autorizado             # ativo, com o aviso legal na tela
sentinela scan alvo.com --autorizado --profundo  # ativo + crawler página a página
```

Para quem opera o dia inteiro sob autorização, as variáveis `SENTINELA_AUTORIZADO=1` e
`SENTINELA_PROFUNDO=1` fazem o mesmo que as flags — inclusive imprimir o aviso. Valor
ambíguo (vazio, `0`, `talvez`) resolve para o lado seguro.

`--profundo` **exige** `--autorizado`: ele percorre o site e diagnostica página a página,
e antes rodava debaixo do rótulo "não-intrusivo" no relatório.

## Rotas com efeito colateral

Nem o crawler nem o probe ativo requisitam rota com cara de ação. O filtro reconhece
inglês **e** português, e quebra o segmento em palavras (hífen, sublinhado, camelCase),
de modo que `/pedidos/1/cancelarPedido`, `/reset-password` e `/conta/exclusao` são
barrados. Rotas descobertas e ignoradas aparecem como `acao-ignorada` no mapa de
superfície.

Na dúvida o filtro barra: uma rota não varrida custa cobertura; uma rota de ação
requisitada custa o estado do ambiente de um cliente.

## Como conferir você mesmo

```bash
sentinela scan SEU-ALVO -f json -o a.json
sentinela scan SEU-ALVO -f json -o b.json
diff a.json b.json     # devem diferir APENAS os carimbos de tempo e o artifact_sha256
```

Medido em duas execuções seguidas contra o mesmo alvo: diferem `started_at`,
`finished_at`, `environment.relogio_utc`, `duration_seconds` (quando a rede varia) e o
`artifact_sha256`. Este último entra na lista porque é o hash do documento inteiro,
carimbos de tempo incluídos: dois laudos que só diferem no relógio têm, corretamente,
selos diferentes. Já `commit` e `ruleset_hash` **têm** de bater — se não batem, as duas
execuções não foram da mesma ferramenta, e a comparação não vale.
