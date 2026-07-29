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
    assert props["owasp_edition"] == "2025"  # o ano é campo, não parsing de string
    assert props["cwe"].startswith("CWE-")
    assert float(props["security-severity"]) > 0
    # achado sem mapeamento não inventa taxonomia
    props_sem = regras["ID_SEM_MAPEAMENTO"]["properties"]
    assert "owasp" not in props_sem
    assert "cwe" not in props_sem


def test_security_severity_e_monotonica_na_severidade() -> None:
    # Era validado só como `> 0`: inverter a tabela inteira (crítico=1.0, info=9.5)
    # passava incólume, e o dashboard do cliente ordenaria os achados ao contrário.
    findings = [
        Finding(
            id=f"ID_{sev.name}",
            title=sev.name,
            category=Category.HEADERS,
            severity=sev,
            description="d",
            recommendation="r",
        )
        for sev in Severity
    ]
    run = json.loads(render_sarif(ScanResult(target=_target(), findings=findings)))["runs"][0]
    valores = [float(r["properties"]["security-severity"]) for r in run["tool"]["driver"]["rules"]]
    # `rules` sai na ordem dos achados ordenados: do mais grave ao menos grave.
    assert valores == sorted(valores, reverse=True)
    assert len(set(valores)) == len(valores)  # nenhuma severidade compartilha o valor


# --------------------------------------------------------------------------- #
# Identidade de achado. O GitHub usa `partialFingerprints` para decidir se dois
# resultados são "logicamente idênticos" E para casar alertas entre execuções. Antes,
# o valor era o próprio rule id: três takeovers CRÍTICOS em hosts diferentes viravam
# UM alerta, e o cliente corrigia um achando que tinha acabado.
# --------------------------------------------------------------------------- #
def _takeover(sub: str) -> Finding:
    return Finding(
        id="SUBDOMAIN_TAKEOVER",
        title=f"Subdomain takeover: {sub}",
        subject=sub,
        category=Category.SURFACE,
        severity=Severity.CRITICAL,
        description=f"`{sub}` aponta para recurso órfão.",
        recommendation="Remova o CNAME.",
        evidence=f"{sub} → abandonado.herokudns.com",
    )


def _fp(run: dict) -> list[str]:  # type: ignore[type-arg]
    return [r["partialFingerprints"]["sentinelaFindingId/v1"] for r in run["results"]]


def test_instancias_distintas_do_mesmo_id_tem_fingerprints_distintos() -> None:
    subs = ["api-old.example.com", "blog.example.com", "loja.example.com"]
    resultado = ScanResult(target=_target(), findings=[_takeover(s) for s in subs], tool_version="0.1.0")
    run = json.loads(render_sarif(resultado))["runs"][0]
    assert len(set(_fp(run))) == 3, "3 takeovers distintos colapsando em menos de 3 alertas"


def test_fingerprint_e_estavel_entre_varreduras_com_evidencia_volatil() -> None:
    # Nonce rotativo na CSP: a evidência muda, o alerta NÃO pode mudar de identidade.
    def _csp(nonce: str) -> ScanResult:
        f = Finding(
            id="CSP_DIRETIVA_INSEGURA",
            title="CSP contém diretivas inseguras",
            category=Category.HEADERS,
            severity=Severity.LOW,
            description="d",
            recommendation="r",
            evidence=f"script-src 'nonce-{nonce}' 'unsafe-inline'",
        )
        return ScanResult(target=_target(), findings=[f], tool_version="0.1.0")

    a = _fp(json.loads(render_sarif(_csp("Ab12Cd34")))["runs"][0])
    b = _fp(json.loads(render_sarif(_csp("Zz98Yy76")))["runs"][0])
    assert a == b


def test_catalogo_de_regras_nao_carrega_hostname_de_instancia() -> None:
    subs = ["api-old.example.com", "blog.example.com"]
    resultado = ScanResult(target=_target(), findings=[_takeover(s) for s in subs], tool_version="0.1.0")
    regras = json.loads(render_sarif(resultado))["runs"][0]["tool"]["driver"]["rules"]
    assert len(regras) == 1  # um descritor por TIPO de problema
    texto = json.dumps(regras, ensure_ascii=False)
    for sub in subs:
        assert sub not in texto, f"o catálogo de regras nomeia a vítima {sub}"
    assert regras[0]["name"] == "SUBDOMAIN_TAKEOVER"


def test_achado_por_host_e_localizado_no_proprio_host() -> None:
    resultado = ScanResult(target=_target(), findings=[_takeover("loja.example.com")], tool_version="0.1.0")
    run = json.loads(render_sarif(resultado))["runs"][0]
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://loja.example.com/"


def test_evidencia_e_impacto_chegam_ao_sarif() -> None:
    # Eram o único formato a perder os dois — justamente os campos acionáveis em CI.
    f = Finding(
        id="COOKIE_SEM_SECURE",
        title="Cookie sem Secure",
        category=Category.COOKIES,
        severity=Severity.MEDIUM,
        description="d",
        recommendation="Adicione Secure.",
        evidence="PHPSESSID, csrftoken",
        impact="Captura na rede.",
    )
    run = json.loads(render_sarif(ScanResult(target=_target(), findings=[f])))["runs"][0]
    assert run["results"][0]["properties"]["evidence"] == "PHPSESSID, csrftoken"
    assert run["results"][0]["properties"]["impact"] == "Captura na rede."
    assert "PHPSESSID, csrftoken" in run["results"][0]["message"]["text"]


def test_nenhum_segredo_ou_achado_produz_documento_vazio_valido() -> None:
    doc = json.loads(render_sarif(ScanResult(target=_target(), tool_version="0.1.0")))
    run = doc["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_sarif_esta_registrado_no_cli() -> None:
    assert "sarif" in {f.value for f in Formato}
    assert _RENDERERS[Formato.sarif] is render_sarif
    assert _EXT[Formato.sarif] == "sarif"
