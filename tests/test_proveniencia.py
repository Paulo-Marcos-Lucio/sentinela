"""Proveniência do laudo: a que código e a que regras o relatório se prende.

O envelope já dizia `version: "0.1.0"` — nome que, sem uma única tag no repositório, já
designou dezenas de árvores diferentes. Com isso, um reteste era AMBÍGUO: "quatro achados
sumiram" tanto podia ser correção do alvo quanto mudança da regra entre as duas execuções.
Estes testes fixam os três selos que desfazem a ambiguidade — e, principalmente, fixam que
eles são REPRODUTÍVEIS por quem recebe o arquivo, porque hash que ninguém consegue
recalcular não prova nada.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from sentinela.core.models import Category, Finding, ScanResult, Severity, Target
from sentinela.core.proveniencia import descobrir_commit, hash_do_catalogo
from sentinela.report import render_json

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _amostra() -> ScanResult:
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
        )
    )
    return result


def test_envelope_carrega_commit_ruleset_hash_e_artifact_sha256(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELA_COMMIT", "a" * 40)
    bruto = render_json(_amostra())
    data = json.loads(bruto)

    assert data["commit"] == "a" * 40
    assert _SHA256.match(data["ruleset_hash"].removeprefix("sha256:"))
    assert _SHA256.match(data["artifact_sha256"])

    # A receita de verificação PUBLICADA tem que fechar: remova o campo do documento e
    # reserialize com as mesmas opções. Sem isto o selo seria decorativo.
    sem_selo = {k: v for k, v in data.items() if k != "artifact_sha256"}
    recalculado = hashlib.sha256(
        json.dumps(sem_selo, ensure_ascii=False, indent=2).encode("utf-8")
    ).hexdigest()
    assert recalculado == data["artifact_sha256"]


def test_artifact_sha256_denuncia_adulteracao(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINELA_COMMIT", "b" * 40)
    data = json.loads(render_json(_amostra()))
    selo = data.pop("artifact_sha256")
    data["summary"]["total"] = 0  # alguém "sumiu" com o achado no arquivo entregue
    adulterado = hashlib.sha256(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")).hexdigest()
    assert adulterado != selo


def test_commit_e_nulo_fora_de_um_repositorio_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Instalação via wheel não tem `.git` — e um laudo sem commit é melhor que um erro.

    O campo vale por dizer a verdade, inclusive a verdade "não sei".
    """
    monkeypatch.delenv("SENTINELA_COMMIT", raising=False)
    assert descobrir_commit(base=tmp_path) is None


def test_variavel_de_ambiente_com_valor_invalido_nao_vira_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Carimbar `commit: "HEAD"` ou `commit: "v2"` seria pior que não carimbar nada:
    # dá aparência de rastreabilidade a um laudo que não é rastreável.
    monkeypatch.setenv("SENTINELA_COMMIT", "nao-e-um-sha")
    assert descobrir_commit(base=tmp_path) is None


def test_commit_do_proprio_repositorio_e_um_sha_de_40_hex(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINELA_COMMIT", raising=False)
    achado = descobrir_commit()
    # Fora de um checkout com git no PATH o valor legítimo é None; o que não se admite é
    # um valor com FORMA de commit que não seja um commit.
    assert achado is None or _SHA40.match(achado)


def test_ruleset_hash_muda_quando_a_taxonomia_do_catalogo_muda(monkeypatch: pytest.MonkeyPatch) -> None:
    """É o teste que separa um selo real de um literal decorativo.

    Sem ele, `ruleset_hash` podia ser uma constante e todos os outros testes passariam —
    e o campo mentiria exatamente na hora em que precisava falar: quando a regra mudou.
    """
    from sentinela.knowledge import mapping

    antes = hash_do_catalogo()
    monkeypatch.setitem(mapping._TAGS, "CSP_AUSENTE", mapping.Tag("A05:2025 Injection", "CWE-79", "XSS"))
    depois = hash_do_catalogo()
    assert antes != depois


def test_ruleset_hash_muda_quando_o_peso_de_uma_severidade_muda(monkeypatch: pytest.MonkeyPatch) -> None:
    # A escala de severidade é regra tanto quanto a taxonomia: mexer no peso de "Alta"
    # muda a nota de todos os laudos futuros sem mudar um único achado.
    from sentinela.core import models

    antes = hash_do_catalogo()
    monkeypatch.setitem(models._SEVERITY_WEIGHTS, Severity.HIGH, 21)
    depois = hash_do_catalogo()
    assert antes != depois
