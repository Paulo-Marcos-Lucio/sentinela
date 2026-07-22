"""Renderizador de terminal usando `rich`."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentinela.core.models import Finding, ScanResult, Severity
from sentinela.knowledge.mapping import tag_for
from sentinela.report._shared import (
    grouped_by_category,
    ordered_counts,
    score_of,
    top_priorities,
)

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_SEV_TAG = {
    Severity.CRITICAL: "CRÍTICA",
    Severity.HIGH: "ALTA",
    Severity.MEDIUM: "MÉDIA",
    Severity.LOW: "BAIXA",
    Severity.INFO: "INFO",
}


def render_console(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    score = score_of(result)

    console.print()
    console.rule(f"[bold]Sentinela[/] · {result.target.host}", style="green")
    console.print()

    modo = "Intrusivo (autorizado)" if result.intrusive else "Não-intrusivo"
    cabecalho = Text.assemble(
        ("Alvo: ", "dim"),
        (f"{result.target.url}\n", "bold"),
        ("Modo: ", "dim"),
        (f"{modo}   ", ""),
        ("Checagens: ", "dim"),
        (f"{len(result.checks_run)}", ""),
    )
    grade_style = _grade_style(score.grade)
    nota = Text(f" {score.grade} ", style=grade_style)
    nota.append(f"  {score.value}/100", style="bold")
    painel = Panel(
        Text.assemble(cabecalho, "\n\n", nota, "\n\n", (score.summary, "italic")),
        title="Diagnóstico",
        border_style="green",
        box=box.ROUNDED,
    )
    console.print(painel)

    tabela = Table(box=box.SIMPLE_HEAVY, show_edge=False, pad_edge=False)
    tabela.add_column("Severidade")
    tabela.add_column("Qtd.", justify="right")
    for sev, qtd in ordered_counts(result):
        estilo = _SEV_STYLE[sev]
        tabela.add_row(Text(sev.label, style=estilo), str(qtd))
    console.print(tabela)
    console.print()

    prioridades = top_priorities(result.findings)
    if prioridades:
        corpo = Text()
        for i, finding in enumerate(prioridades, start=1):
            if i > 1:
                corpo.append("\n\n")
            etiqueta = Text(f" {_SEV_TAG[finding.severity]} ", style=_SEV_STYLE[finding.severity])
            corpo.append_text(Text.assemble((f"{i}. ", "bold"), etiqueta, " ", (finding.title, "bold")))
            corpo.append_text(Text.assemble("\n   → ", (finding.recommendation, "dim")))
        console.print(
            Panel(corpo, title="🎯 Plano de ação — comece por aqui", border_style="green", box=box.ROUNDED)
        )
        console.print()

    if not result.findings:
        console.print("[green]✓ Nenhum achado registrado pelas checagens executadas.[/]")
    else:
        for categoria, findings in grouped_by_category(result.findings).items():
            console.print(f"[bold underline]{categoria.value}[/]")
            for finding in findings:
                _render_finding(console, finding)
            console.print()

    if result.errors:
        console.print("[dim]Observações de execução:[/]")
        for err in result.errors:
            console.print(f"  [dim]• {err.check_id}: {err.message}[/]")
        console.print()


def _render_finding(console: Console, finding: Finding) -> None:
    tag = tag_for(finding.id)
    etiqueta = Text(f" {_SEV_TAG[finding.severity]} ", style=_SEV_STYLE[finding.severity])
    titulo = Text.assemble("  ", etiqueta, " ", (finding.title, "bold"))
    console.print(titulo)

    meta_bits = [f"[dim]{finding.id}[/]"]
    if tag and tag.owasp:
        meta_bits.append(f"[dim]{tag.owasp}[/]")
    if tag and tag.cwe:
        meta_bits.append(f"[dim]{tag.cwe}[/]")
    console.print("     " + " · ".join(meta_bits))
    if finding.evidence:
        console.print(f"     [dim]evidência:[/] {finding.evidence}")
    console.print(f"     [dim]→[/] {finding.recommendation}")


def _grade_style(grade: str) -> str:
    return {
        "A": "bold white on green",
        "B": "bold black on green",
        "C": "bold black on yellow",
        "D": "bold white on dark_orange",
        "F": "bold white on red",
    }.get(grade, "bold")
