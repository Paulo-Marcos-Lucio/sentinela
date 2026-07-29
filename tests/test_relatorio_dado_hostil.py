"""Os 5 renderizadores contra dado 100% controlado pelo alvo.

Uma ferramenta de segurança aponta, POR DEFINIÇÃO, para alvos que podem ser hostis. Nome
de cookie, cabeçalho `Server`, host e mensagem de erro de TLS entram no relatório e são
escolhidos pelo outro lado. Três defeitos reais viviam aqui, e o console nunca era
exercitado por teste nenhum:

* `cart[items]` (nome de cookie estilo PHP/Rails) era impresso como `cart` — evidência
  FACTUALMENTE ERRADA no relatório entregue ao cliente, em silêncio;
* `Server: [/]` (5 bytes) derrubava o relatório com ``MarkupError`` — e o `_emit` da CLI
  não trata exceção, então a varredura inteira era perdida no fim;
* `sid[green]TUDO CERTO[/green]` era renderizado em VERDE no terminal do consultor.

O critério destes testes é LITERALIDADE, não ausência de exceção: o crash é o sintoma
barato, a corrupção silenciosa é a cara.
"""

from __future__ import annotations

import json

import pytest
from rich.console import Console

from sentinela.core.models import Category, Finding, ScanError, ScanResult, Severity, Target
from sentinela.report import render_console, render_html, render_json, render_markdown, render_sarif

# Cada payload é um valor que um alvo real pode devolver.
PAYLOADS = [
    "cart[items]",  # nome de cookie estilo array (PHP/Rails) — corrupção silenciosa
    "sid[/b]",  # tag de fechamento órfã — MarkupError
    "Strict-Transport-Security: max-age=1[/]",  # idem, em cabeçalho
    "sid[green]TUDO CERTO[/green]",  # o alvo escreve em verde no relatório
    "Server: [link=https://evil.example]clique aqui[/link]",  # hyperlink injetado
    "sid` <img src=x onerror=alert(1)> `fim",  # crase: escapa do code span do Markdown
]


def _result(evidencia: str) -> ScanResult:
    target = Target(raw="x", scheme="https", host="alvo.com", port=443, url="https://alvo.com/")
    resultado = ScanResult(target=target, tool_version="0.1.0", checks_run=["cookies"])
    resultado.add(
        Finding(
            id="COOKIE_SEM_SECURE",
            title="Cookie(s) sem flag Secure em site HTTPS",
            category=Category.COOKIES,
            severity=Severity.MEDIUM,
            description="Cookies sem `Secure`.",
            impact="Captura na rede.",
            recommendation="Adicione a flag `Secure`.",
            evidence=evidencia,
        )
    )
    resultado.errors.append(ScanError("tls", evidencia))
    return resultado


def _console_texto(resultado: ScanResult) -> str:
    console = Console(width=200, force_terminal=False, record=True)
    render_console(resultado, console)
    return console.export_text()


@pytest.mark.parametrize("payload", PAYLOADS)
def test_console_imprime_a_evidencia_literal(payload: str) -> None:
    saida = _console_texto(_result(payload))
    assert payload in saida, f"evidência adulterada pelo markup do rich: {payload!r}"


@pytest.mark.parametrize("payload", PAYLOADS)
def test_console_imprime_o_erro_de_execucao_literal(payload: str) -> None:
    # A mensagem de ScanError carrega texto de exceção de rede/TLS — string do servidor.
    assert payload in _console_texto(_result(payload))


def test_console_com_host_hostil_nao_quebra_a_regua() -> None:
    target = Target(raw="x", scheme="https", host="alvo[/].com", port=443, url="https://alvo.com/")
    resultado = ScanResult(target=target, tool_version="0.1.0")
    assert "alvo[/].com" in _console_texto(resultado)


@pytest.mark.parametrize("payload", PAYLOADS)
def test_markdown_preserva_o_byte_e_fecha_o_code_span(payload: str) -> None:
    md = render_markdown(_result(payload))
    linha = next(ln for ln in md.splitlines() if ln.startswith("- **Evidência:**"))
    corpo = linha.removeprefix("- **Evidência:**").strip()
    cerca = corpo[: len(corpo) - len(corpo.lstrip("`"))]
    assert cerca and corpo.endswith(cerca), f"code span não fechado: {linha!r}"
    conteudo = corpo[len(cerca) : -len(cerca)]
    assert conteudo.strip() == payload  # nenhum byte da evidência foi reescrito
    assert cerca not in payload  # e a cerca não aparece dentro do conteúdo


@pytest.mark.parametrize("payload", PAYLOADS)
def test_json_e_sarif_carregam_a_evidencia_intacta(payload: str) -> None:
    dados = json.loads(render_json(_result(payload)))
    assert dados["findings"][0]["evidence"] == payload
    sarif = json.loads(render_sarif(_result(payload)))
    assert sarif["runs"][0]["results"][0]["properties"]["evidence"] == payload


@pytest.mark.parametrize("payload", PAYLOADS)
def test_html_escapa_sem_perder_o_conteudo(payload: str) -> None:
    html = render_html(_result(payload))
    assert "<img src=x onerror" not in html  # o HTML do alvo não vaza para a página
    assert "&lt;img src=x onerror=alert(1)&gt;" in html or "<img" not in payload


def test_html_escapa_script_vindo_do_alvo() -> None:
    # Se alguém trocar `autoescape=True` por `False`, isto fica vermelho.
    html = render_html(_result("<script>alert(1)</script>"))
    assert "&lt;script&gt;" in html
    assert "<script>alert(1)</script>" not in html
