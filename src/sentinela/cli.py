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
from sentinela.report import (
    render_console,
    render_html,
    render_json,
    render_markdown,
    render_sarif,
)
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
    sarif = "sarif"


class Perfil(str, Enum):
    completo = "completo"
    rapido = "rapido"


# Modo rápido: pula as checagens que fazem rede extra além da coleta primária
# (handshakes TLS, consultas DNS, e o fetch do robots.txt) para uma triagem ágil.
_PERFIL_RAPIDO_SKIP = frozenset({"tls", "dns-email", "well-known"})


_EXT = {Formato.markdown: "md", Formato.html: "html", Formato.json: "json", Formato.sarif: "sarif"}
_RENDERERS = {
    Formato.markdown: render_markdown,
    Formato.html: render_html,
    Formato.json: render_json,
    Formato.sarif: render_sarif,
}
# Níveis aceitos por `--falhar-em`. A Sentinela é a única da suíte com superfície bilíngue
# (`--formato`/`--format`, `--pular`/`--skip`); os VALORES seguem o mesmo padrão, para que
# a mesma linha de CI funcione escrita em qualquer um dos dois vocabulários.
_FALHA_SEV: dict[str, Severity | None] = {
    "nenhum": None,
    "none": None,
    "info": Severity.INFO,
    "baixa": Severity.LOW,
    "low": Severity.LOW,
    "media": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "alta": Severity.HIGH,
    "high": Severity.HIGH,
    "critica": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
}


def _nivel_de_falha(valor: str) -> Severity | None:
    chave = valor.strip().lower()
    if chave not in _FALHA_SEV:
        raise typer.BadParameter(
            f"nível desconhecido: {valor!r}. Válidos: {', '.join(_FALHA_SEV)}.",
            param_hint="--falhar-em",
        )
    return _FALHA_SEV[chave]


def _versao_cb(valor: bool) -> None:
    if valor:
        console.print(f"Sentinela v{__version__}")
        raise typer.Exit()


@app.callback()
def _principal(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_versao_cb,
            is_eager=True,
            help="Mostra a versão e sai.",
        ),
    ] = False,
) -> None:
    """Sentinela — diagnóstico de segurança para aplicações web."""


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
            # Não divulgado na ajuda: uso restrito a quem tem autorização por escrito
            # e conhece a trava. Manter o aviso em tempo de execução (mais abaixo).
            hidden=True,
            help="ATIVA checagens intrusivas. Declare somente com autorização por escrito do alvo.",
        ),
    ] = False,
    descobrir: Annotated[
        bool,
        typer.Option(
            "--descobrir",
            "--discover",
            help="Descobre subdomínios via Certificate Transparency (crt.sh) e checa subdomain takeover. Passivo, porém mais lento (consulta serviço externo).",
        ),
    ] = False,
    timeout: Annotated[float, typer.Option(help="Timeout por requisição, em segundos.")] = 8.0,
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
    perfil: Annotated[
        Perfil,
        typer.Option(
            "--perfil",
            "--profile",
            help="`completo` (padrão) roda tudo; `rapido` pula TLS, DNS/e-mail e robots.txt para uma triagem ágil.",
        ),
    ] = Perfil.completo,
    user_agent: Annotated[str | None, typer.Option("--user-agent", help="User-Agent customizado.")] = None,
    falhar_em: Annotated[
        str,
        typer.Option(
            "--falhar-em",
            "--fail-on",
            help=(
                "Código de saída 1 se houver achado >= este nível (útil em CI). "
                "Aceita PT ou EN: nenhum|info|baixa|media|alta|critica."
            ),
        ),
    ] = "alta",
) -> None:
    """Executa uma varredura de diagnóstico no ALVO informado."""
    formatos = formato or [Formato.console]
    limite = _nivel_de_falha(falhar_em)
    try:
        target = parse_target(url)
    except ValueError as exc:
        err_console.print(f"[bold red]Erro:[/] {exc}")
        raise typer.Exit(code=2) from exc

    _valida_ids_de_checagem(somente, pular)

    if descobrir:
        err_console.print(
            "[yellow]Aviso:[/] `--descobrir` consulta o Certificate Transparency e faz "
            "requisições HTTP contra os subdomínios encontrados. O escopo fica limitado ao "
            "domínio do alvo — confirme que ele está dentro da sua autorização."
        )
    if autorizado:
        console.print(
            "[bold yellow]⚠ Modo intrusivo ativado.[/] Você declarou possuir autorização "
            "por escrito para testar este alvo. O uso sem autorização pode configurar crime "
            "(Lei 12.737/2012 c/ Lei 14.155/2021)."
        )
    if sem_verificacao_tls:
        err_console.print("[yellow]Aviso:[/] verificação de certificado TLS desabilitada.")

    skip = set(pular or ())
    if perfil is Perfil.rapido:
        skip |= _PERFIL_RAPIDO_SKIP

    config = ScanConfig(
        intrusive=autorizado,
        discover=descobrir,
        timeout=timeout,
        user_agent=user_agent or USER_AGENT,
        verify_tls=not sem_verificacao_tls,
        skip=frozenset(skip),
        only=frozenset(somente or ()),
    )

    with console.status(f"[green]Analisando {target.host}…", spinner="dots"):
        result = run_scan(target, config)

    _emit(result, formatos, saida)
    _maybe_fail(result, limite, falhar_em)


def _valida_ids_de_checagem(somente: list[str] | None, pular: list[str] | None) -> None:
    """ID inexistente em `--somente`/`--pular` é ERRO DE USO, não varredura silenciosa.

    Antes, `--somente securityheaders` (sem o hífen) rodava ZERO checagens e a ferramenta
    imprimia "Nota 100/100 · A" com código de saída 0 — o pior desfecho possível num
    pipeline: o gate fica verde para sempre e ninguém percebe.
    """
    validos = {cid for cid, _n, _c, _i in all_check_metadata()}
    desconhecidos = sorted((set(somente or ()) | set(pular or ())) - validos)
    if desconhecidos:
        err_console.print(
            f"[bold red]Erro:[/] checagem(ns) desconhecida(s): {', '.join(desconhecidos)}.\n"
            f"IDs válidos: {', '.join(sorted(validos))}."
        )
        raise typer.Exit(code=2)


@app.command()
def regras() -> None:
    """Lista as checagens executadas e o catálogo de achados que elas sabem emitir."""
    from rich.table import Table

    from sentinela.knowledge.mapping import _TAGS

    tabela = Table(title="Checagens da Sentinela")
    tabela.add_column("ID", style="bold")
    tabela.add_column("Nome")
    tabela.add_column("Categoria", style="dim")
    for cid, nome, categoria, intrusiva in all_check_metadata():
        if intrusiva:
            continue
        tabela.add_row(cid, nome, categoria)
    console.print(tabela)

    catalogo = Table(
        title=f"Achados catalogados ({len(_TAGS)})",
        # A severidade NÃO entra: aqui ela é contextual (o mesmo ID sai como Média ou Alta
        # conforme o contexto do alvo). Fixar um valor na tabela seria afirmar o que a
        # ferramenta não sabe antes de ver o alvo.
        caption="A severidade é decidida no contexto de cada alvo — por isso não é listada aqui.",
    )
    catalogo.add_column("ID", style="bold")
    catalogo.add_column("OWASP 2025 / CWE", style="dim")
    for fid, tag in sorted(_TAGS.items()):
        taxonomia = " · ".join(p for p in (tag.owasp, tag.cwe) if p) or "—"
        catalogo.add_row(fid, taxonomia)
    console.print(catalogo)


# Alias histórico: o comando nasceu como `checagens`; `regras` é o nome comum da suíte.
app.command("checagens", hidden=True)(regras)


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


def _maybe_fail(result: ScanResult, limite: Severity | None, rotulo: str) -> None:
    if limite is None:
        return
    if any(f.severity >= limite for f in result.findings):
        err_console.print(f"[red]Achados >= {rotulo} encontrados.[/]")
        raise typer.Exit(code=1)
