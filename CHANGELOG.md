# Changelog

Todas as mudanças notáveis deste projeto são documentadas aqui.

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o
projeto adota [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado
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
- Nota de higiene com teto em **F** quando o certificado está quebrado ou o alvo é inalcançável.
- DNS distingue "consulta falhou" (inconclusivo) de "ausência real", evitando falso-positivo
  de SPF/DMARC sob resolver instável.

### Planejado
- Detecção de bibliotecas front-end desatualizadas (A03 Supply Chain)
- Perfis de varredura (`--perfil rapido|completo`)

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

[Não lançado]: https://github.com/Paulo-Marcos-Lucio/sentinela/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Paulo-Marcos-Lucio/sentinela/releases/tag/v0.1.0
