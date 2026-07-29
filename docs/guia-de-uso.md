# Guia de uso

## Instalação rápida

```bash
pipx install "git+https://github.com/Paulo-Marcos-Lucio/sentinela.git"   # uso
pip install -e ".[dev]"                                                 # desenvolvimento (repo clonado)
sentinela --help
```

## Comandos

| Comando | Descrição |
| --- | --- |
| `sentinela scan <alvo>` | Executa a varredura de diagnóstico. |
| `sentinela regras` | Lista as checagens e o catálogo de achados (com OWASP/CWE). |
| `sentinela versao` | Mostra a versão. |

## Exemplos

```bash
# Diagnóstico padrão (não-intrusivo) no terminal
sentinela scan exemplo.com.br

# Relatório HTML profissional — o entregável do cliente
sentinela scan https://exemplo.com.br -f html -o relatorio.html

# Terminal + Markdown + JSON de uma vez
sentinela scan exemplo.com.br -f console -f markdown -f json

# JSON na saída padrão, para pipelines
sentinela scan exemplo.com.br -f json -o - | jq '.nota'

# Somente as checagens de TLS e cabeçalhos
sentinela scan exemplo.com.br --somente tls --somente security-headers

# Pular a checagem de DNS
sentinela scan exemplo.com.br --pular dns-email

# CI/CD: falha o pipeline se houver achado de severidade alta ou superior
sentinela scan exemplo.com.br --falhar-em alta

# Modo intrusivo — SOMENTE com autorização por escrito
sentinela scan exemplo.com.br --autorizado
```

## Fluxo de um engajamento de consultoria

1. **Diagnóstico** — rode a varredura não-intrusiva e gere o relatório HTML.
2. **Apresentação** — o relatório já traz sumário executivo (para a diretoria) e
   achados priorizados com remediação (para o time técnico).
3. **Correção** — o cliente aplica as recomendações.
4. **Reteste** — nova varredura comprova a redução de risco.
5. **Recorrência** — varredura programada como evidência contínua de gestão de
   vulnerabilidades (útil para a LGPD).

## Integração em CI (GitHub Actions)

```yaml
- name: Diagnóstico de segurança
  run: |
    pip install "git+https://github.com/Paulo-Marcos-Lucio/sentinela.git@<sha-de-40-hex>"
    sentinela scan https://staging.exemplo.com.br --falhar-em alta -f json -o -
```

## Códigos de saída

| Código | Significado |
| --- | --- |
| `0` | Varredura concluída (sem gatilho de `--falhar-em`). |
| `1` | Achado igual ou acima do nível de `--falhar-em`. |
| `2` | Erro de uso: alvo inválido, ID de checagem inexistente ou nível de `--falhar-em` desconhecido. |
| `2` | Alvo inválido. |
