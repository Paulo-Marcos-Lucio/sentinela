"""Invariantes de `Finding.type`/`Finding.confidence` (EV-01).

Três frentes, porque um campo novo com "default seguro" pode quebrar de três jeitos
independentes: o modelo pode não ter o default certo, o renderizador JSON pode esquecer
de emitir o campo (ou emitir a partir de um atributo errado), e o contrato antigo pode
perder uma chave no meio da mudança sem que ninguém repare — os três são testados aqui.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

import sentinela.core.engine as engine
from conftest import make_probe
from sentinela.core.config import ScanConfig
from sentinela.core.models import Category, Confidence, Finding, FindingType, ScanResult, Severity, Target
from sentinela.core.target import parse_target
from sentinela.report import render_json

_CHAVES_DO_CONTRATO_ANTES_DE_EV01 = frozenset(
    {
        "id",
        "title",
        "category",
        "severity",
        "severity_label",
        "severity_rank",
        "subject",
        "owasp",
        "cwe",
        "cwe_name",
        "description",
        "evidence",
        "impact",
        "recommendation",
        "references",
    }
)


def _target() -> Target:
    return Target(raw="x", scheme="https", host="alvo.com", port=443, url="https://alvo.com/")


def _finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "id": "COOKIE_SEM_SECURE",
        "title": "Cookie(s) sem flag Secure em site HTTPS",
        "category": Category.COOKIES,
        "severity": Severity.MEDIUM,
        "description": "Cookies sem `Secure`.",
        "recommendation": "Adicione a flag `Secure`.",
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


def _result(*findings: Finding) -> ScanResult:
    resultado = ScanResult(target=_target(), tool_version="0.1.0", checks_run=["cookies"])
    for f in findings:
        resultado.add(f)
    return resultado


def test_default_e_observation_low_nao_confirmed_high() -> None:
    """O default tem de ser o que MENOS afirma — nunca o que mais afirma.

    Um `Finding()` sem `type`/`confidence` representa uma checagem que ainda não foi
    revisada para classificar (é exatamente o estado de todo achado hoje, antes de
    EV-02/EV-03 percorrerem o catálogo). Cair em CONFIRMED_VULNERABILITY/HIGH por
    omissão infla o relatório com certeza que ninguém verificou; cair em
    OBSERVATION/LOW é o único default que não pode mentir para cima.
    """
    achado = _finding()
    assert achado.type is FindingType.OBSERVATION
    assert achado.confidence is Confidence.LOW


def test_json_traz_type_e_confidence_com_default_seguro_quando_nao_declarado() -> None:
    dados = json.loads(render_json(_result(_finding())))
    achado = dados["findings"][0]
    assert achado["type"] == "observation"
    assert achado["confidence"] == "low"


def test_json_preserva_type_e_confidence_declarados_explicitamente() -> None:
    achado = _finding(
        id="TAKEOVER_CONFIRMADO",
        type=FindingType.CONFIRMED_VULNERABILITY,
        confidence=Confidence.HIGH,
    )
    dados = json.loads(render_json(_result(achado)))["findings"][0]
    assert dados["type"] == "confirmed_vulnerability"
    assert dados["confidence"] == "high"


def test_json_nao_perde_nenhum_campo_do_contrato_anterior() -> None:
    """`sem remover nenhum campo existente do contrato suite-appsec/1` — travado aqui:
    a chave de EV-01 (`type`, `confidence`) é ADITIVA, não uma substituição."""
    dados = json.loads(render_json(_result(_finding())))
    chaves_atuais = set(dados["findings"][0])
    faltando = _CHAVES_DO_CONTRATO_ANTES_DE_EV01 - chaves_atuais
    assert faltando == set(), f"campo(s) do contrato antigo sumiu(ram): {faltando}"
    assert {"type", "confidence"} <= chaves_atuais


@given(tipo=st.sampled_from(list(FindingType)), confianca=st.sampled_from(list(Confidence)))
def test_todo_par_type_confidence_roundtrip_no_json(tipo: FindingType, confianca: Confidence) -> None:
    """Property-based: as 8×3 combinações do enum saem do JSON como o `.value` exato — não
    há mapeamento paralelo em `json_report.py` que possa divergir do enum por um valor."""
    achado = _finding(type=tipo, confidence=confianca)
    dados = json.loads(render_json(_result(achado)))["findings"][0]
    assert dados["type"] == tipo.value
    assert dados["confidence"] == confianca.value


class _ClienteInseguro:
    """Cliente HTTP falso: alvo sem NENHUM cabeçalho de segurança, sem cookies — dispara
    achados reais de várias checagens (não só `Finding`s construídos à mão no teste)."""

    def __init__(self, **_kw: object) -> None:
        self._resposta = make_probe(headers={}, body="<html></html>")

    def __enter__(self) -> _ClienteInseguro:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def get(self, url: str, **_kw: object):  # type: ignore[no-untyped-def]
        return self._resposta

    def request(self, method: str, url: str, **_kw: object):  # type: ignore[no-untyped-def]
        return make_probe(status=404, final_url=url, headers={})

    def close(self) -> None:
        return None


def test_engine_de_ponta_a_ponta_todo_achado_real_tem_type_e_confidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Roda o motor de verdade (não um `Finding` de laboratório) contra um alvo que não
    declara cabeçalho de segurança nenhum — dispara achados de checkers de verdade — e
    confirma que TODO achado emitido, sem exceção, serializa `type`/`confidence` válidos.
    """
    monkeypatch.setattr(engine, "HttpClient", _ClienteInseguro)
    resultado = engine.run_scan(
        parse_target("https://alvo.com/"),
        ScanConfig(only=frozenset({"security-headers", "cookies"})),
    )
    assert resultado.findings, "cenário insegura precisa gerar achado real para o teste valer algo"
    dados = json.loads(render_json(resultado))
    tipos_validos = {t.value for t in FindingType}
    confiancas_validas = {c.value for c in Confidence}
    for achado in dados["findings"]:
        assert achado["type"] in tipos_validos, achado
        assert achado["confidence"] in confiancas_validas, achado
