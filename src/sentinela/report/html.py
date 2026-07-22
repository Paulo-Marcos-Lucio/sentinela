"""Renderizador de relatório HTML autocontido (CSS inline), pronto para o cliente."""

from __future__ import annotations

from importlib.resources import files

from jinja2 import Environment

from sentinela.core.models import ScanResult
from sentinela.knowledge.mapping import tag_for
from sentinela.report._shared import (
    grouped_by_category,
    ordered_counts,
    score_of,
    top_priorities,
)

_TEMPLATE = files("sentinela.report").joinpath("templates/report.html.j2").read_text("utf-8")


def render_html(result: ScanResult) -> str:
    score = score_of(result)

    counts = [{"label": sev.label, "qtd": qtd, "color": sev.color} for sev, qtd in ordered_counts(result)]
    total = sum(qtd for _, qtd in ordered_counts(result))

    priorities = [
        {
            "title": f.title,
            "severity": f.severity.label,
            "severity_color": f.severity.color,
            "recommendation": f.recommendation,
        }
        for f in top_priorities(result.findings)
    ]

    groups = []
    for categoria, findings in grouped_by_category(result.findings).items():
        items = []
        for f in findings:
            tag = tag_for(f.id)
            items.append(
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.label,
                    "severity_color": f.severity.color,
                    "owasp": tag.owasp if tag else None,
                    "cwe": tag.cwe if tag else None,
                    "cwe_name": tag.cwe_name if tag else None,
                    "description": f.description,
                    "evidence": f.evidence,
                    "impact": f.impact,
                    "recommendation": f.recommendation,
                    "references": list(f.references),
                }
            )
        groups.append({"category": categoria.value, "findings": items})

    # autoescape=True explícito: dados controlados pelo alvo (headers, cookies, CORS)
    # entram no relatório e precisam ser escapados independentemente do nome do template.
    env = Environment(autoescape=True)
    template = env.from_string(_TEMPLATE)
    return template.render(
        target=result.target,
        mode="Intrusivo (autorizado)" if result.intrusive else "Não-intrusivo",
        tool_version=result.tool_version,
        generated_at=result.started_at.strftime("%d/%m/%Y %H:%M UTC"),
        score=score,
        counts=counts,
        total=total,
        priorities=priorities,
        groups=groups,
        checks_run=len(result.checks_run),
        errors=[{"check": e.check_id, "message": e.message} for e in result.errors],
    )
