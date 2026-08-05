# Política de Segurança e Uso Ético

## Uso autorizado

A **Sentinela** é uma ferramenta de **avaliação defensiva**, destinada a analisar
sistemas que você **possui** ou para os quais tem **autorização explícita e por
escrito** para testar.

- O **modo padrão é não-intrusivo**: apenas observa o que o servidor já expõe a
  qualquer visitante (cabeçalhos HTTP, handshake TLS, consultas DNS públicas).
- O **modo intrusivo** (`--autorizado`) é uma decisão consciente do operador, que
  declara possuir autorização. Sem essa flag, nenhuma checagem ativa roda.

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

- E-mail: **pmlsp23@gmail.com** (assunto: `[security] sentinela`)

Peço a gentileza de **não** abrir uma issue pública antes de darmos tempo para uma
correção. Reconheço o recebimento e trabalho a correção com prioridade, coordenando
a divulgação com quem reportou.

## Escopo

Esta política cobre o código deste repositório. Ela **não** autoriza o uso da
ferramenta contra terceiros sem consentimento.
