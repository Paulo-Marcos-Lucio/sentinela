# Changelog

Todas as mudanças notáveis deste projeto são documentadas aqui.

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o
projeto adota [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Planejado
- Detecção de bibliotecas front-end desatualizadas (A03 Supply Chain)
- Verificação de Subresource Integrity (SRI)
- Exportação para SARIF

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
