"""Higiene de publicacao da vitrine — trava por teste o posicionamento honesto (Classe A).

A auditoria cruzada Pro (2026-09-12) achou o mesmo defeito de MENSAGEM na suite: o README
publico afirmava EM ABSOLUTO que "nao ha motor escondido no privado" / "a mesma engine, sem
uma linha a mais" enquanto as branches `pro/motor-*` carregam codigo de deteccao exclusivo. A
Sentinela ja usava o frame honesto e removeu a super-generalizacao ("no resto da suite a engine
publica e a mesma"); a rodada 1 corrigiu o TEXTO. Este teste TRAVA a classe: se qualquer frase
absolutista voltar ao README publico enquanto o Pro tem deteccao exclusiva, o portao fica
vermelho — o cetico pegou, no guardiao, que so corrigir o texto sem travar e decorativo.

Invariante A: o README publico nunca afirma absolutismo de "engine identica"/"nao ha motor
escondido". Prova a CLASSE (lista de formas proibidas), nao o exemplo.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_RAIZ = Path(__file__).resolve().parents[1]

# READMEs client-facing (vitrine). Ambos entram na trava; o EN tem suas proprias formas.
_READMES_PUBLICOS = ("README.md", "README.en.md")

# Formas absolutistas PROIBIDAS (case-insensitive). Fonte: SPEC-RODADA2-FECHAMENTO-2026-09-15,
# ampliada com a versao EN das mesmas afirmacoes. Qualquer uma nega o que o repo Pro comprova.
_FRASES_ABSOLUTISTAS_PROIBIDAS = (
    "sem uma linha a mais",
    "não há motor",
    "nao ha motor",
    "nem checagem que só nasce",
    "nem checagem que so nasce",
    "a mesma engine",
    "engine idêntica",
    "engine identica",
    "no resto da suíte a engine pública é a mesma",
    "nenhuma capacidade escondida",
    # Formas EN equivalentes (a vitrine tem toggle de idioma; o absoluto nao pode voltar por la).
    "the public engine is the same",
    "not a single line more",
    "no hidden engine",
    "the same engine",
)


def _texto_publico(nome: str) -> str:
    return (_RAIZ / nome).read_text(encoding="utf-8").lower()


@pytest.mark.parametrize("readme", _READMES_PUBLICOS)
def test_readme_publico_sem_frase_absolutista(readme: str) -> None:
    """Nenhuma forma absolutista de 'engine identica / nao ha motor escondido' aparece no
    README publico — enquanto `pro/motor-*` tem deteccao/flag ausente de `main`, o absoluto
    e falso e nao pode ser publicado."""
    conteudo = _texto_publico(readme)
    presentes = [f for f in _FRASES_ABSOLUTISTAS_PROIBIDAS if f.lower() in conteudo]
    assert not presentes, f"{readme} contem frase(s) absolutista(s) proibida(s): {presentes}"


def test_a_trava_realmente_pega_uma_frase_plantada() -> None:
    """Meta-teste anti-decorativo (o cetico faz a mutacao): plantar uma frase proibida num
    texto TEM de ser detectado pela mesma logica. Se este teste passar com a frase ausente,
    a trava seria fachada."""
    texto_limpo = "a versao publica faz deteccao passiva honesta; o Pro adiciona codigo a mais."
    texto_sujo = texto_limpo + " no fundo e a mesma engine, sem uma linha a mais."
    achadas_limpo = [f for f in _FRASES_ABSOLUTISTAS_PROIBIDAS if f.lower() in texto_limpo]
    achadas_sujo = [f for f in _FRASES_ABSOLUTISTAS_PROIBIDAS if f.lower() in texto_sujo.lower()]
    assert achadas_limpo == []
    assert "a mesma engine" in achadas_sujo and "sem uma linha a mais" in achadas_sujo
