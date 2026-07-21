"""Renderizador JSON — saída legível por máquina (integração CI/CD, dashboards)."""

from __future__ import annotations

import json

from sentinela.core.models import Finding, ScanResult
from sentinela.knowledge.mapping import tag_for
from sentinela.report._shared import ordered_counts, score_of


def render_json(result: ScanResult) -> str:
    score = score_of(result)
    payload = {
        "ferramenta": "sentinela",
        "versao": result.tool_version,
        "alvo": {
            "url": result.target.url,
            "host": result.target.host,
            "porta": result.target.port,
            "esquema": result.target.scheme,
        },
        "modo": "intrusivo" if result.intrusive else "nao-intrusivo",
        "iniciado_em": result.started_at.isoformat(),
        "finalizado_em": result.finished_at.isoformat() if result.finished_at else None,
        "duracao_segundos": round(result.duration_seconds, 2),
        "checagens_executadas": result.checks_run,
        "nota": {"valor": score.value, "conceito": score.grade, "resumo": score.summary},
        "contagem_por_severidade": {sev.label: qtd for sev, qtd in ordered_counts(result)},
        "achados": [_finding_dict(f) for f in result.sorted_findings()],
        "erros": [{"checagem": e.check_id, "mensagem": e.message} for e in result.errors],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def _finding_dict(finding: Finding) -> dict[str, object]:
    tag = tag_for(finding.id)
    return {
        "id": finding.id,
        "titulo": finding.title,
        "categoria": finding.category.value,
        "severidade": finding.severity.label,
        "severidade_nivel": int(finding.severity),
        "owasp": tag.owasp if tag else None,
        "cwe": tag.cwe if tag else None,
        "descricao": finding.description,
        "evidencia": finding.evidence,
        "impacto": finding.impact,
        "recomendacao": finding.recommendation,
        "referencias": list(finding.references),
    }
