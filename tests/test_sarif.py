"""Testes do renderizador SARIF 2.1.0."""

from __future__ import annotations

import json

from sentinela.cli import _EXT, _RENDERERS, Formato
from sentinela.core.models import Category, Finding, ScanResult, Severity, Target
from sentinela.report.sarif import render_sarif


def _target() -> Target:
    return Target(
        raw="example.com",
        scheme="https",
        host="example.com",
        port=443,
        url="https://example.com/",
    )


def _result_com_achados() -> ScanResult:
    findings = [
        Finding(
            id="CONTEUDO_MISTO",
            title="Conteúdo misto",
            category=Category.CONTENT,
            severity=Severity.MEDIUM,
            description="A página HTTPS carrega sub-recursos por HTTP.",
            recommendation="Sirva todos os recursos por HTTPS.",
            references=("https://developer.mozilla.org/Mixed_content",),
        ),
        Finding(
            id="ID_SEM_MAPEAMENTO",
            title="Achado sem taxonomia",
            category=Category.SURFACE,
            severity=Severity.INFO,
            description="Achado informativo.",
            recommendation="Nenhuma ação necessária.",
        ),
    ]
    return ScanResult(target=_target(), findings=findings, tool_version="0.1.0")


def test_documento_e_sarif_210_valido() -> None:
    doc = json.loads(render_sarif(_result_com_achados()))
    assert doc["version"] == "2.1.0"
    assert "sarif-2.1.0" in doc["$schema"]
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "sentinela"
    assert driver["version"] == "0.1.0"


def test_resultados_ordenados_por_severidade_e_localizados_pela_url() -> None:
    run = json.loads(render_sarif(_result_com_achados()))["runs"][0]
    results = run["results"]
    assert [r["ruleId"] for r in results] == ["CONTEUDO_MISTO", "ID_SEM_MAPEAMENTO"]
    # o mais grave (Média → "warning") vem antes do informativo ("note")
    assert results[0]["level"] == "warning"
    assert results[1]["level"] == "note"
    loc = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert loc["uri"] == "https://example.com/"


def test_regras_carregam_taxonomia_quando_existe() -> None:
    run = json.loads(render_sarif(_result_com_achados()))["runs"][0]
    regras = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    # achado mapeado leva OWASP + CWE + security-severity
    props = regras["CONTEUDO_MISTO"]["properties"]
    assert props["owasp"].startswith("A0")
    assert props["cwe"].startswith("CWE-")
    assert float(props["security-severity"]) > 0
    # achado sem mapeamento não inventa taxonomia
    props_sem = regras["ID_SEM_MAPEAMENTO"]["properties"]
    assert "owasp" not in props_sem
    assert "cwe" not in props_sem


def test_nenhum_segredo_ou_achado_produz_documento_vazio_valido() -> None:
    doc = json.loads(render_sarif(ScanResult(target=_target(), tool_version="0.1.0")))
    run = doc["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_sarif_esta_registrado_no_cli() -> None:
    assert "sarif" in {f.value for f in Formato}
    assert _RENDERERS[Formato.sarif] is render_sarif
    assert _EXT[Formato.sarif] == "sarif"
