"""Testes de modelos (Severity, Finding, ScanResult) e pontuação."""

from __future__ import annotations

import pytest

from sentinela.core.models import Category, Finding, ScanResult, Severity, Target
from sentinela.core.scoring import compute_score


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
    score = compute_score([_finding(Severity.CRITICAL)])
    assert score.value == 60  # 100 - 40
    assert score.grade == "C"


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
