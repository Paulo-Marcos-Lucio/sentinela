"""Renderizador de relatório HTML autocontido (CSS inline), pronto para o cliente."""

from __future__ import annotations

import re
from importlib.resources import files

from jinja2 import Environment
from markupsafe import Markup, escape

from sentinela.core.models import ScanResult
from sentinela.core.proveniencia import descobrir_commit, hash_do_catalogo
from sentinela.knowledge.mapping import tag_for
from sentinela.knowledge.plain import INTRO_LEIGO, plain_for
from sentinela.report._shared import (
    grouped_by_category,
    ordered_counts,
    score_of,
    top_priorities,
)


def _emphasize(text: str) -> Markup:
    """Converte **negrito** em <strong>. Seguro: o texto é ESCAPADO antes e é uma
    constante da própria ferramenta (INTRO_LEIGO), nunca dado controlado pelo alvo."""
    escaped = str(escape(text))  # neutraliza qualquer HTML antes de reintroduzir só o <strong>
    return Markup(re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped))  # noqa: S704


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
                    "analogia": plain_for(f.id),
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
        # Proveniência no entregável humano (o HTML/PDF circula fora da equipe): commit diz
        # QUAL código rodou; ruleset_hash, QUAL catálogo. Sem eles o laudo não é vinculável.
        commit=descobrir_commit(),
        ruleset_hash=hash_do_catalogo(),
        score=score,
        counts=counts,
        total=total,
        priorities=priorities,
        intro_leigo=_emphasize(INTRO_LEIGO),
        groups=groups,
        checks_run=len(result.checks_run),
        errors=[{"check": e.check_id, "message": e.message} for e in result.errors],
    )
