"""`review` — onde a revisão humana do laudo fica registrada (EV-06).

Antes deste campo, o trabalho humano que o cliente paga — a revisão do consultor
antes de fechar o laudo — não aparecia em lugar nenhum do entregável. Um achado
"olhado e confirmado por um especialista" e um achado cru, recém-saído da
varredura automática, saíam do JSON exatamente iguais.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

import sentinela.cli as cli
import sentinela.core.engine as engine
from sentinela.core.http import Probe
from sentinela.core.models import Category, Finding, Review, ScanResult, Severity, Target

runner = CliRunner()


def _target() -> Target:
    return Target(raw="x", scheme="https", host="alvo.com", port=443, url="https://alvo.com/")


def _finding(fid: str = "X", **review_kwargs: object) -> Finding:
    kwargs: dict[str, object] = {
        "id": fid,
        "title": "t",
        "category": Category.HEADERS,
        "severity": Severity.LOW,
        "description": "d",
        "recommendation": "r",
    }
    if review_kwargs:
        kwargs["review"] = Review(**review_kwargs)  # type: ignore[arg-type]
    return Finding(**kwargs)  # type: ignore[arg-type]


# --- Default: nenhum achado nasce revisado -------------------------------- #


def test_default_e_nao_revisado() -> None:
    f = _finding()
    assert f.review == Review(reviewed=False, reviewer=None, disposition=None, note=None)


def test_json_default_traz_review_com_reviewed_false() -> None:
    from sentinela.report import render_json

    result = ScanResult(target=_target(), tool_version="0.1.0")
    result.add(_finding("CSP_AUSENTE"))
    achado = json.loads(render_json(result))["findings"][0]
    assert achado["review"] == {
        "reviewed": False,
        "reviewer": None,
        "disposition": None,
        "note": None,
    }


# --- `ScanResult.mark_reviewed` — o caminho que preenche o revisor -------- #


def test_mark_reviewed_preenche_reviewed_e_reviewer_em_todos() -> None:
    result = ScanResult(target=_target())
    result.add(_finding("A"))
    result.add(_finding("B"))

    result.mark_reviewed("Paulo Marcos Lucio")

    assert len(result.findings) == 2
    for f in result.findings:
        assert f.review.reviewed is True
        assert f.review.reviewer == "Paulo Marcos Lucio"


def test_mark_reviewed_rejeita_revisor_vazio() -> None:
    result = ScanResult(target=_target())
    result.add(_finding("A"))
    with pytest.raises(ValueError):
        result.mark_reviewed("")


def test_mark_reviewed_preserva_disposition_e_note_existentes() -> None:
    """Chamar `mark_reviewed` não pode apagar uma anotação já presente no achado —
    ainda que hoje nenhuma checagem preencha `disposition`/`note`, o método não pode
    presumir que sempre estarão vazios."""
    result = ScanResult(target=_target())
    result.add(_finding("A", disposition="falso_positivo", note="ambiente de teste"))

    result.mark_reviewed("Paulo Marcos Lucio")

    achado = result.findings[0]
    assert achado.review.reviewed is True
    assert achado.review.reviewer == "Paulo Marcos Lucio"
    assert achado.review.disposition == "falso_positivo"
    assert achado.review.note == "ambiente de teste"


@given(nome=st.text(min_size=1, max_size=80))
def test_mark_reviewed_nunca_muda_nada_alem_de_review(nome: str) -> None:
    """Invariante: para QUALQUER nome de revisor não-vazio, `mark_reviewed` mexe
    exclusivamente em `review` — id, title, category, severity e todo o resto do
    achado saem bit-a-bit iguais. Sem isso, um bug em `mark_reviewed` poderia
    corromper achados calados, sem teste nenhum notando."""
    original = _finding("HSTS_AUSENTE")
    result = ScanResult(target=_target())
    result.add(original)

    result.mark_reviewed(nome)

    revisado = result.findings[0]
    assert revisado.id == original.id
    assert revisado.title == original.title
    assert revisado.category == original.category
    assert revisado.severity == original.severity
    assert revisado.description == original.description
    assert revisado.recommendation == original.recommendation
    assert revisado.review.reviewed is True
    assert revisado.review.reviewer == nome


# --- Ponta a ponta: CLI real, motor real, sem rede ------------------------- #

_CABECALHOS_RUINS = {"Content-Type": "text/html", "Server": "nginx/1.18.0"}


class _ClienteFalso:
    def __init__(self, **_kwargs: object) -> None:
        pass

    def request(self, method: str, url: str, **_kwargs: object) -> Probe:
        return Probe(
            url=url,
            status_code=200,
            headers=dict(_CABECALHOS_RUINS),
            body_snippet="<html><body>oi</body></html>",
            final_url=url,
        )

    def get(self, url: str, **kwargs: object) -> Probe:
        return self.request("GET", url, **kwargs)

    def close(self) -> None:
        return

    def __enter__(self) -> _ClienteFalso:
        return self

    def __exit__(self, *exc: object) -> None:
        return


@pytest.fixture(autouse=True)
def _sem_rede(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "HttpClient", _ClienteFalso)


def _scan(*args: str) -> object:
    return runner.invoke(
        cli.app,
        ["scan", "https://exemplo.com", "--somente", "security-headers", "--falhar-em", "nenhum", *args],
    )


def test_cli_sem_revisor_mantem_o_default() -> None:
    resultado = _scan("-f", "json", "-o", "-")
    assert resultado.exit_code == 0
    dados = json.loads(resultado.stdout[resultado.stdout.index("{") :])
    assert dados["findings"]
    for achado in dados["findings"]:
        assert achado["review"]["reviewed"] is False
        assert achado["review"]["reviewer"] is None


def test_cli_com_revisor_preenche_o_revisor_em_todo_achado() -> None:
    resultado = _scan("-f", "json", "-o", "-", "--revisor", "Paulo Marcos Lucio")
    assert resultado.exit_code == 0
    dados = json.loads(resultado.stdout[resultado.stdout.index("{") :])
    assert dados["findings"]
    for achado in dados["findings"]:
        assert achado["review"]["reviewed"] is True
        assert achado["review"]["reviewer"] == "Paulo Marcos Lucio"
