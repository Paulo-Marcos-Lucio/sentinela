# Guia de uso

## Instalação rápida

```bash
pip install -e ".[dev]"     # a partir do repositório clonado
sentinela --help
```

## Comandos

| Comando | Descrição |
| --- | --- |
| `sentinela scan <alvo>` | Executa a varredura de diagnóstico. |
| `sentinela checagens` | Lista todas as checagens disponíveis. |
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
    pip install sentinela-scan
    sentinela scan https://staging.exemplo.com.br --falhar-em alta -f json -o -
```

## Códigos de saída

| Código | Significado |
| --- | --- |
| `0` | Varredura concluída (sem gatilho de `--falhar-em`). |
| `1` | Achado igual ou acima do nível de `--falhar-em`. |
| `2` | Alvo inválido. |
