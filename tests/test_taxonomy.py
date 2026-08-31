"""Invariante de sincronia entre `knowledge/mapping.py` e a fonte declarativa em `taxonomy/`.

Existe porque, até este teste, o mapeamento OWASP/CWE só morava no Python — quem
precisasse consumir a taxonomia sem importar o pacote (um dashboard, um script de
outro repo, um humano lendo diff) não tinha onde olhar, e `mapping.py` podia divergir
de qualquer cópia feita à mão em outro lugar sem que nada acusasse. `taxonomy/*.yaml`
é a fonte declarativa; este teste é o que tranca a sincronia — muda um lado sem mudar
o outro e o CI para.

Leitura de YAML é dependência só de teste (`PyYAML` em `[project.optional-dependencies].dev`):
`mapping.py` não ganha import novo nem lê o arquivo em runtime.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from sentinela.knowledge.mapping import _TAGS, OWASP_EDICAO, OWASP_TOP10_2025

_RAIZ = Path(__file__).resolve().parent.parent
_TAXONOMY = _RAIZ / "taxonomy"


def _carrega(nome: str) -> object:
    return yaml.safe_load((_TAXONOMY / nome).read_text(encoding="utf-8"))


def test_owasp_2025_yaml_existe_e_carrega() -> None:
    doc = _carrega("owasp-2025.yaml")
    assert isinstance(doc, dict)
    assert "edicao" in doc
    assert "categorias" in doc


def test_edicao_bate_com_owasp_edicao() -> None:
    # Comparação de string, de propósito: `OWASP_EDICAO = "2025"` é a mesma string que
    # entra no JSON/SARIF. Se o YAML guardar `2025` sem aspas, o PyYAML devolve um int
    # e a comparação já falha aqui — é o sinal certo (o arquivo está errado), não um
    # falso-negativo silencioso.
    doc = _carrega("owasp-2025.yaml")
    assert doc["edicao"] == OWASP_EDICAO


def test_categorias_batem_com_owasp_top10_2025() -> None:
    """Mesma ordem, mesmo id, mesmo rótulo — divergir em qualquer um dos três é o defeito
    que este teste existe para pegar (ex.: um rótulo editado só de um dos dois lados)."""
    doc = _carrega("owasp-2025.yaml")
    rotulos_yaml = [c["rotulo"] for c in doc["categorias"]]
    assert tuple(rotulos_yaml) == OWASP_TOP10_2025

    ids_yaml = [c["id"] for c in doc["categorias"]]
    ids_esperados = [rotulo.split(":", 1)[0] for rotulo in OWASP_TOP10_2025]
    assert ids_yaml == ids_esperados


def test_mappings_yaml_existe_e_carrega() -> None:
    doc = _carrega("mappings.yaml")
    assert isinstance(doc, dict)
    assert doc  # o dict real tem 78 entradas hoje; vazio é o parser quebrado, não um repo limpo


def test_todo_achado_do_codigo_esta_no_yaml_com_a_mesma_classificacao() -> None:
    """`_TAGS` é a lista de achados que o motor de fato conhece. Um achado novo (ou uma
    reclassificação) que não chegou no YAML é exatamente o cenário que motivou o item:
    o Python muda e a fonte declarativa fica velha sem ninguém perceber."""
    doc = _carrega("mappings.yaml")
    divergentes = {}
    for finding_id, tag in _TAGS.items():
        entrada = doc.get(finding_id)
        se_no_yaml = {
            "owasp": entrada.get("owasp") if entrada else None,
            "cwe": entrada.get("cwe") if entrada else None,
            "cwe_name": entrada.get("cwe_name") if entrada else None,
        }
        no_codigo = {"owasp": tag.owasp, "cwe": tag.cwe, "cwe_name": tag.cwe_name}
        if entrada is None or se_no_yaml != no_codigo:
            divergentes[finding_id] = {"yaml": se_no_yaml if entrada else None, "codigo": no_codigo}
    assert divergentes == {}


def test_yaml_nao_tem_achado_orfao() -> None:
    """O inverso do teste acima: uma entrada que sobrevive no YAML depois de o achado
    sumir do código (checker removido/renomeado) é lixo — a fonte declarativa mentiria
    sobre o que o motor emite."""
    doc = _carrega("mappings.yaml")
    orfaos = sorted(set(doc) - set(_TAGS))
    assert orfaos == []
