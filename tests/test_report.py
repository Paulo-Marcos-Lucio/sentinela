"""Testes dos renderizadores de relatório."""

from __future__ import annotations

import json

from sentinela.core.models import Category, Finding, ScanResult, Severity, Target
from sentinela.report import render_html, render_json, render_markdown


def _sample() -> ScanResult:
    target = Target(raw="x", scheme="https", host="alvo.com", port=443, url="https://alvo.com/")
    result = ScanResult(target=target, tool_version="0.1.0", checks_run=["security-headers"])
    result.add(
        Finding(
            id="CSP_AUSENTE",
            title="Content-Security-Policy ausente",
            category=Category.HEADERS,
            severity=Severity.MEDIUM,
            description="Sem CSP.",
            impact="XSS.",
            recommendation="Implante uma CSP.",
            references=("https://developer.mozilla.org/x",),
        )
    )
    return result


def test_markdown_contem_secoes_e_taxonomia() -> None:
    md = render_markdown(_sample())
    assert "# Relatório de Diagnóstico de Segurança — alvo.com" in md
    assert "Content-Security-Policy ausente" in md
    assert "A02:2025 Security Misconfiguration" in md
    assert "Lei 12.737/2012" in md  # cláusula legal presente


def test_json_estruturado_valido() -> None:
    data = json.loads(render_json(_sample()))
    assert data["ferramenta"] == "sentinela"
    assert data["alvo"]["host"] == "alvo.com"
    assert data["achados"][0]["id"] == "CSP_AUSENTE"
    assert data["achados"][0]["owasp"] == "A02:2025 Security Misconfiguration"
    assert data["nota"]["conceito"] in {"A", "B", "C", "D", "F"}


def test_html_autocontido_e_seguro() -> None:
    html = render_html(_sample())
    assert html.startswith("<!doctype html>")
    assert "Content-Security-Policy ausente" in html
    assert "Sumário executivo" in html
    # sem dependências externas (CSP-friendly): nada de <script src> ou http externo de asset
    assert "<script" not in html


def test_relatorio_vazio() -> None:
    target = Target(raw="x", scheme="https", host="alvo.com", port=443, url="https://alvo.com/")
    vazio = ScanResult(target=target, tool_version="0.1.0")
    assert "Nenhum achado" in render_markdown(vazio)
    assert json.loads(render_json(vazio))["achados"] == []
