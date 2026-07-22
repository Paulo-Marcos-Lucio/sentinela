"""Interface de linha de comando da Sentinela."""

from __future__ import annotations

import contextlib
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from sentinela.core.config import ScanConfig
from sentinela.core.engine import run_scan
from sentinela.core.http import USER_AGENT
from sentinela.core.models import ScanResult, Severity
from sentinela.core.registry import all_check_metadata
from sentinela.core.target import parse_target
from sentinela.report import render_console, render_html, render_json, render_markdown
from sentinela.version import __version__


def _ensure_utf8() -> None:
    """Força UTF-8 na saída para não quebrar em consoles Windows legados (cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):  # dependente do SO
                reconfigure(encoding="utf-8", errors="replace")


_ensure_utf8()

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="sentinela",
    help="Sentinela — diagnóstico de segurança para aplicações web.",
    no_args_is_help=True,
    add_completion=False,
)


class Formato(str, Enum):
    console = "console"
    markdown = "markdown"
    html = "html"
    json = "json"


class NivelFalha(str, Enum):
    nenhum = "nenhum"
    baixa = "baixa"
    media = "media"
    alta = "alta"
    critica = "critica"


_EXT = {Formato.markdown: "md", Formato.html: "html", Formato.json: "json"}
_RENDERERS = {
    Formato.markdown: render_markdown,
    Formato.html: render_html,
    Formato.json: render_json,
}
_FALHA_SEV = {
    NivelFalha.baixa: Severity.LOW,
    NivelFalha.media: Severity.MEDIUM,
    NivelFalha.alta: Severity.HIGH,
    NivelFalha.critica: Severity.CRITICAL,
}


@app.command()
def scan(
    url: Annotated[str, typer.Argument(help="Alvo: domínio ou URL (ex.: exemplo.com.br).")],
    formato: Annotated[
        list[Formato] | None,
        typer.Option("--formato", "--format", "-f", help="Formato(s) de saída. Repetível."),
    ] = None,
    saida: Annotated[
        Path | None,
        typer.Option("--saida", "--output", "-o", help="Arquivo de saída (para 1 formato de arquivo)."),
    ] = None,
    autorizado: Annotated[
        bool,
        typer.Option(
            "--autorizado",
            "--authorized",
            help="ATIVA checagens intrusivas. Declare somente com autorização por escrito do alvo.",
        ),
    ] = False,
    timeout: Annotated[float, typer.Option(help="Timeout por requisição, em segundos.")] = 15.0,
    sem_verificacao_tls: Annotated[
        bool,
        typer.Option(
            "--sem-verificacao-tls",
            "--no-verify-tls",
            help="INSEGURO: desabilita a validação de certificado TLS em todas as conexões (sujeito a MITM). Os achados de TLS ainda são reportados.",
        ),
    ] = False,
    pular: Annotated[
        list[str] | None,
        typer.Option("--pular", "--skip", help="IDs de checagem a pular. Repetível."),
    ] = None,
    somente: Annotated[
        list[str] | None,
        typer.Option("--somente", "--only", help="Roda somente estes IDs. Repetível."),
    ] = None,
    user_agent: Annotated[str | None, typer.Option("--user-agent", help="User-Agent customizado.")] = None,
    falhar_em: Annotated[
        NivelFalha,
        typer.Option(
            "--falhar-em",
            "--fail-on",
            help="Código de saída 1 se houver achado >= este nível (útil em CI).",
        ),
    ] = NivelFalha.alta,
) -> None:
    """Executa uma varredura de diagnóstico no ALVO informado."""
    formatos = formato or [Formato.console]
    try:
        target = parse_target(url)
    except ValueError as exc:
        err_console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=2) from exc

    if autorizado:
        console.print(
            "[bold yellow]⚠ Modo intrusivo ativado.[/] Você declarou possuir autorização "
            "por escrito para testar este alvo. O uso sem autorização pode configurar crime "
            "(Lei 12.737/2012 c/ Lei 14.155/2021)."
        )
    if sem_verificacao_tls:
        err_console.print("[yellow]Aviso:[/] verificação de certificado TLS desabilitada.")

    config = ScanConfig(
        intrusive=autorizado,
        timeout=timeout,
        user_agent=user_agent or USER_AGENT,
        verify_tls=not sem_verificacao_tls,
        skip=frozenset(pular or ()),
        only=frozenset(somente or ()),
    )

    with console.status(f"[green]Analisando {target.host}…", spinner="dots"):
        result = run_scan(target, config)

    _emit(result, formatos, saida)
    _maybe_fail(result, falhar_em)


@app.command()
def checagens() -> None:
    """Lista todas as checagens disponíveis."""
    from rich.table import Table

    tabela = Table(title="Checagens da Sentinela")
    tabela.add_column("ID", style="bold")
    tabela.add_column("Nome")
    tabela.add_column("Categoria", style="dim")
    tabela.add_column("Intrusiva", justify="center")
    for cid, nome, categoria, intrusiva in all_check_metadata():
        tabela.add_row(cid, nome, categoria, "sim" if intrusiva else "—")
    console.print(tabela)


@app.command()
def versao() -> None:
    """Mostra a versão da ferramenta."""
    console.print(f"Sentinela v{__version__}")


def _emit(result: ScanResult, formatos: list[Formato], saida: Path | None) -> None:
    file_formats = [f for f in formatos if f is not Formato.console]

    if Formato.console in formatos:
        render_console(result, console)

    single = len(file_formats) == 1
    for fmt in file_formats:
        conteudo = _RENDERERS[fmt](result)
        # `-o -` escreve na saída padrão (útil para pipelines: `... -f json -o -`).
        if single and saida is not None and str(saida) == "-":
            sys.stdout.write(conteudo + "\n")
            continue
        destino = (
            saida if (single and saida is not None) else Path(f"sentinela-{result.target.host}.{_EXT[fmt]}")
        )
        destino.write_text(conteudo, encoding="utf-8")
        console.print(f"[green]✓[/] Relatório {fmt.value} salvo em [bold]{destino}[/]")


def _maybe_fail(result: ScanResult, falhar_em: NivelFalha) -> None:
    if falhar_em is NivelFalha.nenhum:
        return
    limite = _FALHA_SEV[falhar_em]
    if any(f.severity >= limite for f in result.findings):
        err_console.print(f"[red]Achados >= {falhar_em.value} encontrados.[/]")
        raise typer.Exit(code=1)
