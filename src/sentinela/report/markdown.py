"""Renderizador de relatório em Markdown — entregável portátil e versionável."""

from __future__ import annotations

import re
from collections.abc import Callable

from sentinela.core.models import Finding, ScanResult, Severity
from sentinela.knowledge.mapping import tag_for
from sentinela.report._shared import grouped_by_category, ordered_counts, score_of

_CRASES_RE = re.compile(r"`+")


def _code_span(texto: str) -> str:
    """Embrulha ``texto`` num code span de Markdown SEM alterar um byte do conteúdo.

    A evidência vem do alvo e pode conter crase. Com a cerca fixa de uma crase, um valor
    como ``sid` <img src=x onerror=alert(1)> `fim`` ESCAPA do span e vira HTML quando o
    .md é renderizado por um terceiro (GitHub, wiki do cliente). Reescrever as crases
    resolveria o escape, mas ADULTERARIA a evidência — o pecado que esta ferramenta
    existe para não cometer. A regra do CommonMark permite as duas coisas: a cerca só
    precisa ser maior que a maior sequência de crases do conteúdo.
    """
    maior = max((len(m.group()) for m in _CRASES_RE.finditer(texto)), default=0)
    cerca = "`" * (maior + 1)
    espaco = " " if texto.startswith("`") or texto.endswith("`") else ""
    return f"{cerca}{espaco}{texto}{espaco}{cerca}"


_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def render_markdown(result: ScanResult) -> str:
    score = score_of(result)
    lines: list[str] = []
    a = lines.append

    a(f"# Relatório de Diagnóstico de Segurança — {result.target.host}")
    a("")
    a(
        f"> Gerado pela **Sentinela v{result.tool_version}** · "
        f"{result.started_at.strftime('%d/%m/%Y %H:%M UTC')}"
    )
    a("")
    a("| Item | Valor |")
    a("| --- | --- |")
    a(f"| Alvo | `{result.target.url}` |")
    a(f"| Modo | {'Intrusivo (autorizado)' if result.intrusive else 'Não-intrusivo'} |")
    a(f"| Checagens executadas | {len(result.checks_run)} |")
    a(f"| Nota de higiene | **{score.value}/100 · Conceito {score.grade}** |")
    a("")

    a("## Sumário executivo")
    a("")
    a(score.summary)
    a("")
    a("| Severidade | Qtd. |")
    a("| --- | --- |")
    for sev, qtd in ordered_counts(result):
        a(f"| {_SEV_EMOJI[sev]} {sev.label} | {qtd} |")
    a("")

    if not result.findings:
        a("Nenhum achado registrado pelas checagens executadas. ✅")
    else:
        a("## Achados")
        a("")
        for categoria, findings in grouped_by_category(result.findings).items():
            a(f"### {categoria.value}")
            a("")
            for finding in findings:
                _render_finding(a, finding)

    if result.errors:
        a("## Observações de execução")
        a("")
        for err in result.errors:
            a(f"- `{err.check_id}`: {err.message}")
        a("")

    a("---")
    a("")
    a("### Metodologia e limites")
    a("")
    a(
        "Este relatório resulta de checagens **não-intrusivas** (salvo modo intrusivo "
        "explicitamente autorizado) que observam o que o servidor expõe a um cliente "
        "comum. A nota de higiene é um indicador transparente, **não** um escore CVSS "
        "formal, e a ausência de achados não garante inexistência de vulnerabilidades — "
        "falhas de lógica, injeção e autorização exigem teste manual dedicado."
    )
    a("")
    a(
        "Conduzido sob autorização e dentro do escopo acordado, em conformidade com a "
        "Lei 12.737/2012, a Lei 14.155/2021, o Marco Civil da Internet (Lei 12.965/2014) "
        "e a LGPD (Lei 13.709/2018)."
    )
    a("")
    return "\n".join(lines)


def _render_finding(a: Callable[[str], None], finding: Finding) -> None:
    tag = tag_for(finding.id)
    a(f"#### {_SEV_EMOJI[finding.severity]} {finding.title}")
    a("")
    meta = [f"**Severidade:** {finding.severity.label}", f"**ID:** `{finding.id}`"]
    if tag and tag.owasp:
        meta.append(f"**OWASP:** {tag.owasp}")
    if tag and tag.cwe:
        meta.append(f"**{tag.cwe}**" + (f" ({tag.cwe_name})" if tag.cwe_name else ""))
    a(" · ".join(meta))
    a("")
    a(finding.description)
    a("")
    if finding.evidence:
        a(f"- **Evidência:** {_code_span(finding.evidence)}")
    if finding.impact:
        a(f"- **Impacto:** {finding.impact}")
    a(f"- **Recomendação:** {finding.recommendation}")
    if finding.references:
        refs = " · ".join(f"[ref]({url})" for url in finding.references)
        a(f"- **Referências:** {refs}")
    a("")
