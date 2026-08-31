<p align="center"><a href="SECURITY.en.md"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/sentinela/main/assets/btn-lang-en.svg" alt="Read this document in English" width="300"/></a></p>

# Política de Segurança e Uso Ético

## Uso autorizado

A **Sentinela** é uma ferramenta de **avaliação defensiva**, destinada a analisar
sistemas que você **possui** ou para os quais tem **autorização explícita e por
escrito** para testar.

- O **modo padrão é não-intrusivo**: apenas observa o que o servidor já expõe a
  qualquer visitante (cabeçalhos HTTP, handshake TLS, consultas DNS públicas).
- O **modo intrusivo** (`--autorizado`) é uma decisão consciente do operador, que
  declara possuir autorização. Sem essa flag, o **fuzzing de rotas/arquivos sensíveis,
  a sondagem de API e a de erro verboso não rodam** (são as checagens marcadas como
  intrusivas). As checagens passivas rodam sempre; e a postura padrão é de baixo toque —
  a descoberta de subdomínios exige `--descobrir`, e o inventário de métodos faz um
  único `OPTIONS`. Em resumo: nada de fuzzing sem `--autorizado`, mas "passivo" aqui
  significa baixo impacto, não zero pacote.

### Enquadramento legal (Brasil)

O acesso não autorizado a dispositivo informático é crime no Brasil:

- **Lei 12.737/2012** (Carolina Dieckmann — art. 154-A do Código Penal): tipifica a
  invasão de dispositivo informático.
- **Lei 14.155/2021**: aumentou as penas e removeu do tipo a exigência de "violação
  indevida de mecanismo de segurança" — ou seja, o acesso sem **autorização
  expressa ou tácita** pode configurar crime mesmo sem quebrar controles.
- **Lei 12.965/2014** (Marco Civil da Internet) e **Lei 13.709/2018** (LGPD) regem
  privacidade e o tratamento de qualquer dado pessoal eventualmente encontrado.

A **autorização por escrito, com escopo definido** (domínios/IPs, janela de tempo,
técnicas permitidas), é o elemento que descaracteriza o ilícito. Documente-a antes
de qualquer teste.

## Divulgação responsável

Encontrou uma vulnerabilidade **nesta ferramenta**? Por favor, reporte de forma
privada:

- E-mail: **contatopml26@gmail.com** (assunto: `[security] sentinela`)

Peço a gentileza de **não** abrir uma issue pública antes de darmos tempo para uma
correção. Reconheço o recebimento e trabalho a correção com prioridade, coordenando
a divulgação com quem reportou.

## Escopo

Esta política cobre o código deste repositório. Ela **não** autoriza o uso da
ferramenta contra terceiros sem consentimento.

## Modelo de ameaças da suíte

A Sentinela fala HTTP com um alvo escolhido pelo operador — e esse alvo pode ser
hostil. [`docs/modelo-de-ameacas.md`](docs/modelo-de-ameacas.md) documenta como a
ferramenta se defende de um alvo que tenta usar a própria varredura como vetor
(bomba de descompressão, ReDoS em HTML hostil, SSRF via redirecionamento) — com o
teste que tranca cada defesa — e declara os gaps que ainda não estão fechados. É o
modelo de ameaça da suíte AppSec inteira ([Guardião](https://github.com/Paulo-Marcos-Lucio/guardiao),
[Chaveiro](https://github.com/Paulo-Marcos-Lucio/chaveiro),
[Esteira](https://github.com/Paulo-Marcos-Lucio/esteira) e
[Laboratório OWASP](https://github.com/Paulo-Marcos-Lucio/laboratorio-owasp)),
publicado aqui porque é a Sentinela quem tem a superfície de rede.
