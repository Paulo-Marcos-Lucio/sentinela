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
    # Contrato `suite-appsec/1`: chaves e valores de identificador em EN, texto em PT-BR.
    # A Sentinela era a única das quatro emitindo chaves em português e severidade
    # acentuada ("Média"), obrigando o consumidor a manter um de-para só para ela.
    data = json.loads(render_json(_sample()))
    assert data["schema"] == "suite-appsec/1"
    assert data["tool"] == "sentinela"
    assert data["owasp_edition"] == "2025"
    assert data["target"]["host"] == "alvo.com"
    achado = data["findings"][0]
    assert achado["id"] == "CSP_AUSENTE"
    assert achado["severity"] == "medium"  # identificador, sem acento
    assert achado["severity_label"] == "Média"  # rótulo humano
    assert achado["severity_rank"] == 2
    assert achado["owasp"] == "A02:2025 Security Misconfiguration"
    assert data["summary"]["score"]["grade"] in {"A", "B", "C", "D", "F"}
    # `EV-04`: achado passivo nunca alega prova, e sempre declara o que não demonstra.
    assert achado["exploitability_proven"] is False
    assert achado["not_proven"]


def test_json_by_severity_traz_sempre_as_cinco_chaves() -> None:
    # Um dashboard que soma by_severity["critical"] não pode quebrar num relatório limpo.
    resumo = json.loads(render_json(_sample()))["summary"]
    assert set(resumo["by_severity"]) == {"critical", "high", "medium", "low", "info"}
    assert resumo["by_severity"]["critical"] == 0
    assert resumo["by_severity"]["medium"] == 1
    assert resumo["total"] == 1


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
    dados = json.loads(render_json(vazio))
    assert dados["findings"] == []
    assert set(dados["summary"]["by_severity"]) == {"critical", "high", "medium", "low", "info"}
