"""Testes de modelos (Severity, Finding, ScanResult) e pontuação."""

from __future__ import annotations

import pytest

from sentinela.core.models import Category, Finding, ScanResult, Severity, Target
from sentinela.core.scoring import _CERT_QUEBRADO, _grade_for, compute_score


def _finding(sev: Severity, fid: str = "X") -> Finding:
    return Finding(
        id=fid,
        title="t",
        category=Category.HEADERS,
        severity=sev,
        description="d",
        recommendation="r",
    )


def test_severity_ordenacao_e_rotulo() -> None:
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    assert Severity.CRITICAL.label == "Crítica"
    assert Severity.INFO.weight == 0
    assert Severity.CRITICAL.weight > Severity.HIGH.weight


def test_severity_from_name_pt_e_en() -> None:
    assert Severity.from_name("critica") is Severity.CRITICAL
    assert Severity.from_name("HIGH") is Severity.HIGH
    assert Severity.from_name("Informativa") is Severity.INFO
    with pytest.raises(ValueError):
        Severity.from_name("inexistente")


def test_finding_valida_campos() -> None:
    with pytest.raises(ValueError):
        _finding(Severity.LOW, fid="")


def test_scan_result_contagem_e_ordenacao() -> None:
    target = Target(raw="x", scheme="https", host="x", port=443, url="https://x/")
    result = ScanResult(target=target)
    result.add(_finding(Severity.LOW, "a"))
    result.add(_finding(Severity.CRITICAL, "b"))
    result.add(_finding(Severity.MEDIUM, "c"))
    counts = result.counts_by_severity()
    assert counts[Severity.CRITICAL] == 1
    assert counts[Severity.LOW] == 1
    # o mais grave vem primeiro
    assert result.sorted_findings()[0].severity is Severity.CRITICAL


def test_score_sem_achados_e_nota_maxima() -> None:
    score = compute_score([])
    assert score.value == 100
    assert score.grade == "A"


def test_score_penaliza_por_severidade() -> None:
    # O VALOR continua sendo 100 − soma dos pesos (reconstruível à mão)…
    score = compute_score([_finding(Severity.CRITICAL)])
    assert score.value == 60  # 100 - 40
    # …mas o CONCEITO é tetado pela gravidade: um achado CRÍTICO nunca pode ler "C".
    # (Este teste afirmava `grade == "C"`: era o contrato errado, não o código.)
    assert score.grade == "F"


def test_score_piso_zero() -> None:
    achados = [_finding(Severity.CRITICAL, f"c{i}") for i in range(5)]
    assert compute_score(achados).value == 0


def test_score_info_nao_penaliza() -> None:
    assert compute_score([_finding(Severity.INFO)]).value == 100


def test_score_cert_quebrado_teta_em_f() -> None:
    # Um único HIGH normal daria B (100-20=80); com falha de confiança TLS, teto em F.
    s = compute_score([_finding(Severity.HIGH, "CERT_EXPIRADO")])
    assert s.grade == "F"
    assert s.value <= 44


def test_score_alvo_inacessivel_nao_infla_a_nota() -> None:
    # Incapacidade de avaliar NÃO pode virar nota boa (era o bug de inversão).
    s = compute_score([_finding(Severity.HIGH, "ALVO_INACESSIVEL")])
    assert s.grade == "F"
    assert "incompleta" in s.summary.lower()


def test_score_hostname_invalido_teta_em_f() -> None:
    assert compute_score([_finding(Severity.HIGH, "CERT_HOSTNAME_INVALIDO")]).grade == "F"


# --------------------------------------------------------------------------- #
# Contrato da NOTA. Estas três tabelas existem porque a nota e o conceito são o
# produto: é o primeiro número que o cliente lê na capa do relatório. Antes delas,
# 10 de 12 mutações nos pesos e nas fronteiras sobreviviam com a suíte verde —
# `MEDIUM` podia valer 39 em vez de 8 e o CI aplaudia. Cada linha ancora um número
# EXATO; desigualdade (`<= 44`) não trava nada.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("severidade", "peso"),
    [
        (Severity.CRITICAL, 40),
        (Severity.HIGH, 20),
        (Severity.MEDIUM, 8),
        (Severity.LOW, 3),
        (Severity.INFO, 0),
    ],
)
def test_peso_de_cada_severidade_e_o_publicado(severidade: Severity, peso: int) -> None:
    assert severidade.weight == peso


@pytest.mark.parametrize(
    ("valor", "conceito"),
    [
        (100, "A"),
        (90, "A"),
        (89, "B"),
        (75, "B"),
        (74, "C"),
        (60, "C"),
        (59, "D"),
        (45, "D"),
        (44, "F"),
        (0, "F"),
    ],
)
def test_fronteiras_de_conceito(valor: int, conceito: str) -> None:
    # As 4 fronteiras testadas dos DOIS lados — é isso que mata o `>= 90` virar `>= 89`.
    assert _grade_for(valor) == conceito


# Os IDs vêm LITERAIS de propósito: derivá-los de `_CERT_QUEBRADO` faria o teste
# encolher junto com a remoção de um ID — a mutação sobreviveria (medido).
@pytest.mark.parametrize("cert_id", ["CERT_EXPIRADO", "CERT_NAO_CONFIAVEL", "CERT_HOSTNAME_INVALIDO"])
def test_teto_de_cert_quebrado_e_exatamente_40(cert_id: str) -> None:
    assert cert_id in _CERT_QUEBRADO
    assert compute_score([_finding(Severity.HIGH, cert_id)]).value == 40


def test_conceito_e_tetado_pela_gravidade_sem_mexer_no_valor() -> None:
    # O valor continua sendo 100 − soma dos pesos; só o conceito reprova por gravidade.
    critico = compute_score([_finding(Severity.CRITICAL, "DOTENV_EXPOSTO")])
    assert (critico.value, critico.grade) == (60, "F")
    alto = compute_score([_finding(Severity.HIGH, "SEM_HTTPS")])
    assert (alto.value, alto.grade) == (80, "D")
    # E o relatório precisa EXPLICAR a divergência entre número e letra.
    assert "conceito" in alto.summary.lower() and "gravidade" in alto.summary.lower()
    # Sem achado grave, conceito e valor concordam (o teto não vaza para o caso comum).
    medio = compute_score([_finding(Severity.MEDIUM, "CSP_AUSENTE")])
    assert (medio.value, medio.grade) == (92, "A")


def test_nota_e_monotonica_acrescentar_achado_nunca_melhora() -> None:
    # Rede de segurança contra recalibração futura da curva.
    lista: list[Finding] = []
    anterior = compute_score(lista).value
    for i, sev in enumerate([Severity.LOW, Severity.MEDIUM, Severity.INFO, Severity.HIGH] * 4):
        lista.append(_finding(sev, f"id{i}"))
        atual = compute_score(lista).value
        assert atual <= anterior
        anterior = atual
