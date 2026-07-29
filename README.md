<a href="https://paulo-marcos-lucio.github.io"><img src="https://raw.githubusercontent.com/Paulo-Marcos-Lucio/sentinela/main/assets/banner-abismo-v2.svg" alt="Sentinela — o olho que vela a superfície da sua aplicação: diagnóstico externo de segurança web (TLS, cabeçalhos, cookies, CORS, DNS/e-mail, subdomínios)" width="100%"/></a>

<div align="center">

# 🛡️ Sentinela

### Diagnóstico não-intrusivo de segurança para aplicações web — com relatório pronto para o cliente.

*Descubra em segundos como o servidor da sua aplicação se expõe na internet: cabeçalhos de segurança, TLS/certificado, cookies, CORS, métodos HTTP, exposição de informação e segurança de DNS/e-mail — mapeado ao **OWASP Top 10:2025** e entregue como um relatório profissional.*

[![CI](https://github.com/Paulo-Marcos-Lucio/sentinela/actions/workflows/ci.yml/badge.svg)](https://github.com/Paulo-Marcos-Lucio/sentinela/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ruff](https://img.shields.io/badge/lint-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-2A6DB2.svg)](https://mypy-lang.org/)
[![OWASP Top 10:2025](https://img.shields.io/badge/OWASP-Top%2010%3A2025-000000.svg)](https://owasp.org/Top10/2025/)

</div>

---

## 📌 O problema

A maioria dos vazamentos e incidentes em PMEs e fintechs **não** começa por uma técnica sofisticada de invasão. Começa pelo básico mal configurado: um `.env` esquecido na raiz do site, um certificado prestes a vencer, cookies de sessão sem `HttpOnly`, um CORS que devolve dados autenticados para qualquer origem, um domínio sem SPF que vira vetor de phishing.

Esse "básico" é justamente o que um diagnóstico bem-feito encontra **antes** do atacante — e é o que a **Sentinela** automatiza, transformando uma varredura em um relatório que o time técnico entende e que a diretoria consegue ler.

> **Por que isso é urgente no Brasil?** A LGPD (art. 46) exige medidas técnicas de segurança **e a prova, datada e efetiva, de que elas existem**. A ANPD está em ciclo fiscalizatório e já multou empresas de todos os portes. Um diagnóstico recorrente de vulnerabilidades é uma dessas evidências — e é fator atenuante que a ANPD pondera na dosimetria de eventual sanção.

---

## ✨ O que a Sentinela verifica

| Módulo | O que analisa | OWASP 2025 |
| --- | --- | --- |
| **Cabeçalhos** | HSTS, CSP com **análise profunda** (curinga, `object-src`, `base-uri`, `report-only`), X-Content-Type-Options, X-Frame-Options / clickjacking, Referrer-Policy, Permissions-Policy, COOP, X-XSS-Protection legado | A02 |
| **TLS / Certificado** | Protocolos legados (TLS 1.0/1.1), **ausência de TLS 1.3**, cifra **sem Perfect Forward Secrecy**, certificado expirado/expirando, hostname divergente, chave RSA fraca, assinatura obsoleta, cadeia não confiável | A04 |
| **Transporte** | Redirecionamento de HTTP → HTTPS | A04 |
| **Cookies** | Flags `Secure`, `HttpOnly`, `SameSite` — inclui `SameSite=None` inseguro e prefixos `__Host-`/`__Secure-` | A01 / A04 / A07 |
| **CORS** | Reflexão de origem, curinga com credenciais, políticas permissivas | A01 |
| **Métodos HTTP** | `TRACE` (XST), métodos de escrita expostos (`PUT`/`DELETE`) | A02 |
| **Exposição de info** | Versão de servidor/stack vazada, listagem de diretório | A02 |
| **Conteúdo da página** | Conteúdo misto (*mixed content*), ausência de **SRI** em recursos de terceiros, formulário com `action` insegura, campo de senha sem HTTPS | A03 / A04 |
| **Arquivos públicos** | `robots.txt` (RFC 9309) revelando caminhos sensíveis por convenção | A02 |
| **Superfície de ataque** | Descoberta de subdomínios via **Certificate Transparency** e detecção de **subdomain takeover** (CNAME órfão) — opt-in `--descobrir` | A02 |
| **DNS / E-mail** | SPF, DMARC (política), CAA, DNSSEC, **MTA-STS**, **TLS-RPT** | A02 / A04 / A07 |

Cada achado vem com **severidade** (ancorada nas faixas do CVSS), **evidência**, **impacto**, **recomendação prática** e **referências** (OWASP, MDN, RFC), além da classificação **OWASP Top 10:2025 + CWE**.

---

## 🚀 Instalação

Requer **Python 3.10+**.

A Sentinela **não está publicada no PyPI**, então `pip install sentinela` NÃO instala esta
ferramenta — esse nome pertence a outro projeto (um watchdog de sistema operacional). A
instalação é direto do repositório:

```bash
# via pipx (recomendado: ambiente isolado, comando global)
pipx install "git+https://github.com/Paulo-Marcos-Lucio/sentinela.git"

# ou via pip
pip install "git+https://github.com/Paulo-Marcos-Lucio/sentinela.git"

# a partir do código-fonte, para desenvolvimento (com ruff, mypy, pytest)
git clone https://github.com/Paulo-Marcos-Lucio/sentinela.git
cd sentinela
pip install -e ".[dev]"
```

Ou rode isolado, sem instalar, via Docker:

```bash
docker build -t sentinela .
docker run --rm sentinela scan exemplo.com.br
```

---

## 🧑‍💻 Uso

```bash
# varredura padrão (não-intrusiva) com saída no terminal
sentinela scan exemplo.com.br

# gerar o relatório HTML profissional (o entregável do cliente)
sentinela scan https://exemplo.com.br -f html -o relatorio-exemplo.html

# vários formatos de uma vez
sentinela scan exemplo.com.br -f console -f markdown -f json

# uso em CI/CD: falha o pipeline se houver achado de severidade alta ou superior
sentinela scan exemplo.com.br --falhar-em alta

# descobrir subdomínios via Certificate Transparency (passivo, mais lento)
sentinela scan exemplo.com.br --descobrir

# listar as checagens e o catálogo de achados
sentinela regras

# versão
sentinela --version
```

Principais opções do `scan`:

| Opção | Descrição |
| --- | --- |
| `-f, --formato` | `console` (padrão), `markdown`, `html`, `json`, `sarif`. Repetível. |
| `-o, --saida` | Arquivo de saída para um formato de arquivo. |
| `--falhar-em` / `--fail-on` | `nenhum`/`info`/`baixa`/`media`/`alta`/`critica` (ou `none`/`info`/`low`/`medium`/`high`/`critical`) — código de saída 1 para CI. Padrão: `alta`. |
| `--timeout` | Timeout por requisição, em segundos (padrão 8). |
| `--pular` / `--somente` | Filtra quais checagens rodam (por ID). ID inexistente → erro de uso (saída 2). |
| `--perfil` | `completo` (padrão) roda tudo; `rapido` pula TLS, DNS/e-mail e robots.txt (triagem ágil). |
| `--descobrir` | Enumera subdomínios via Certificate Transparency e checa subdomain takeover. Passivo, porém mais lento. |
| `--sem-verificacao-tls` | **INSEGURO**: desabilita a validação de certificado nas conexões (sujeito a MITM). Os achados de TLS continuam sendo reportados. |

**Códigos de saída:** `0` varredura concluída · `1` achado no nível de `--falhar-em` ou acima · `2` erro de uso (alvo inválido, ID de checagem inexistente, nível desconhecido).

**Padrão de `--fail-on` na suíte** — os defaults NÃO são iguais, e isso é deliberado:

| Ferramenta | Padrão | Por quê |
| --- | --- | --- |
| Sentinela | `alta` | Cabeçalho ausente é hardening; o gate fecha no que representa risco real. |
| Guardião | `media` | Scanner de SEGREDO: a faixa média é onde moram CPF/CNPJ (LGPD) e strings de alta entropia. A consequência de uma credencial vazada é categoricamente pior — o gatilho tem que ser mais sensível. |
| Chaveiro | `alta` | Análise de um token individual. |
| Esteira | `alta` | Configuração de CI. |

📄 **Veja um relatório real de exemplo:** [`docs/exemplo-relatorio.md`](docs/exemplo-relatorio.md)

---

## 🔓 Versão Pro (privada) — a leitura que cruza a linha

O que está aqui é a **vitrine**: o diagnóstico **não-intrusivo**, aberto e defensivo. A **versão Pro é privada** — de propósito. Ela destrava a leitura profunda, e uma capacidade dessas na mão de qualquer um é risco, não recurso:

- 🕸️ **Modo profundo (crawler):** mapeia a **aplicação inteira** — páginas servidas, rotas de SPA lidas direto do bundle e endpoints — e diagnostica **página a página**, não só a URL que você digitou. Reconhece, categoriza e mostra a superfície toda daquele mesmo jeito didático (o que é · por que importa · como corrigir).
- 👁️ **Sondagem ativa** de dezenas de rotas e artefatos sensíveis (muito além do modo aberto);
- 🧭 **Análise E confirmação ativa da API:** enumera as operações do contrato OpenAPI, aponta as sem autenticação e **confirma no ar** — bate no endpoint sem credencial e prova se a auth é aplicada de fato (acabou o "achismo" da análise estática). Mapeia também pontos de **reflexão de parâmetro** (superfície de XSS), tudo read-only e sem tocar em rotas de ação;
- 🐛 **Detecção de modo debug e erro verboso**, provocando o servidor com segurança (read-only).

É a diferença entre ler a fachada e **enxergar por dentro da superfície** — sempre sob autorização e escopo.

> **É a sua aplicação que precisa desse nível?** Faço o diagnóstico completo, a correção e o reteste — com a régua de quem veio do **backend financeiro regulado** (Pix, Open Finance, FAPI).

<div align="center">

[![Pacotes e valores](https://img.shields.io/badge/Pacotes_e_valores-paulo--marcos--lucio.github.io-0f766e?style=for-the-badge)](https://paulo-marcos-lucio.github.io)
[![Falar no LinkedIn](https://img.shields.io/badge/LinkedIn-Falar_agora-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/paulo-marcos-a07379174/)

</div>

---

## 🗺️ Como isso vira valor numa consultoria

A Sentinela foi desenhada para ser o **primeiro passo de um engajamento**, não o último:

1. **Diagnóstico relâmpago** — rode a varredura não-intrusiva e entregue o relatório HTML. Baixo atrito, alto impacto: o cliente *vê* os problemas.
2. **Priorização** — os achados já vêm ordenados por severidade e com recomendação prática, virando um plano de correção.
3. **Correção e reteste** — aplicadas as correções, uma nova varredura comprova a redução de risco (o reteste é entregável esperado do mercado).
4. **Recorrência** — varredura programada como evidência contínua de gestão de vulnerabilidades para a LGPD.

> A varredura automatizada **não substitui** um pentest manual — falhas de lógica de negócio, injeção e autorização exigem teste humano dedicado. A Sentinela cobre com profundidade a camada de **configuração e higiene** (OWASP A02 e A04), que é onde mora a maior parte dos problemas de baixo custo e alto impacto.

---

## 🏗️ Arquitetura

Projeto em camadas, com cada checagem isolada e testável:

```
src/sentinela/
├── core/          # modelos, motor, cliente HTTP, configuração, pontuação
├── checks/        # uma checagem por arquivo, todas herdando de Checker
├── report/        # renderizadores: console (rich), markdown, html (jinja2), json, sarif
├── knowledge/     # referências canônicas + taxonomia OWASP/CWE
└── cli.py         # interface typer
```

As checagens **nunca** falam com a rede diretamente: recebem um objeto `Probe` imutável, o que as torna testáveis sem tocar na internet e concentra timeouts/erros num único lugar. Uma falha em uma checagem individual é capturada e registrada — nunca derruba a varredura inteira.

---

## ⚖️ Uso ético e autorização

**Esta ferramenta é para avaliação de sistemas que você possui ou tem autorização explícita e por escrito para testar.**

- O **modo padrão é não-intrusivo**: só observa o que o servidor já expõe a um visitante comum (cabeçalhos, TLS, consultas DNS públicas).
- Mesmo assim, **rode apenas contra domínios que você possui ou tem autorização por escrito para avaliar**. Volume de requisições e registro em log são do dono do sistema, não seus.
- No Brasil, o acesso não autorizado a dispositivo informático é crime (**Lei 12.737/2012**, agravada pela **Lei 14.155/2021**). A **autorização por escrito, com escopo definido**, é o que descaracteriza o ilícito. Considere ainda o **Marco Civil da Internet** (Lei 12.965/2014) e a **LGPD** (Lei 13.709/2018) ao tratar qualquer dado encontrado.

Use com responsabilidade. Veja [`SECURITY.md`](SECURITY.md) para divulgação responsável.

---

## 🧭 Roadmap

- [ ] Detecção de bibliotecas front-end desatualizadas (fingerprint) — A03 Supply Chain
- [x] Verificação de Subresource Integrity (SRI) em scripts de terceiros
- [x] Alerta de *dangling CNAME* / subdomain takeover (descoberta via Certificate Transparency, opt-in `--descobrir`)
- [x] Exportação para **SARIF 2.1.0** (`-f sarif`) — ingestável pela aba *Security* do GitHub
- [x] Perfis de varredura (`--perfil completo|rapido`)

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Veja [`CONTRIBUTING.md`](CONTRIBUTING.md). Rode a suíte de qualidade antes de abrir um PR:

```bash
ruff check . && ruff format --check . && mypy src && pytest
```

## 📄 Licença

[MIT](LICENSE) © 2026 Paulo Marcos Lucio.

---

<div align="center">

### 👋 Sobre o autor

**Paulo Marcos Lucio** — desenvolvedor com background em **sistemas financeiros regulados** (Pix, Open Finance, autenticação FAPI/mTLS) que hoje atua em **segurança de aplicações web**: diagnóstico e correção de vulnerabilidades, hardening e prevenção de falhas.

**Precisa de um diagnóstico de segurança na sua aplicação web?**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Conversar-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/paulo-marcos-a07379174/)
[![Email](https://img.shields.io/badge/E--mail-pmlsp23%40gmail.com-EA4335?logo=gmail&logoColor=white)](mailto:pmlsp23@gmail.com)
[![Site](https://img.shields.io/badge/Site-paulo--marcos--lucio.github.io-0f766e)](https://paulo-marcos-lucio.github.io)

</div>
