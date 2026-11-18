"""Escopo de A01:2025 Broken Access Control — trava contra over-claim de IDOR.

Auditoria FN/FP 2026-09-08, item AUD0908-fn-idor-e-a01-fora-de-cobertura-do-motor: a
tabela do README tagueia Cookies/CORS/Forms com `A01`, mas nenhum desses achados é IDOR
(controle de acesso por objeto). Um motor black-box sem autenticação não tem como testar
IDOR de verdade — precisaria de múltiplas identidades autenticadas e de uma especificação
de qual resposta é "autorizada" para não virar FP/FN sem base. O risco não é um achado
errado, é a LEITURA: alguém vendo "A01" na tabela pode concluir que IDOR está coberto.

Este teste trava a CLASSE, não o exemplo: (1) o conjunto de achados tagueados A01 tem
de ser EXATAMENTE o conjunto hoje conhecido (CSRF + CORS) — um achado novo tagueado A01
quebra o teste até alguém decidir, de propósito, se ele é a mesma classe (atualiza a
allowlist) ou é IDOR de verdade (precisa de spec, não é black-box puro); (2) a declaração
explícita de exclusão de IDOR tem de aparecer nas mesmas frases-chave em TODOS os lugares
que fazem a promessa pública (código, metodologia PT, README PT, README EN) — se uma
dessas cópias for editada e a ressalva for perdida, o teste pega.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sentinela.knowledge.mapping import _TAGS, A01, A01_ESCOPO

_RAIZ = Path(__file__).resolve().parent.parent

# Único conjunto de achados hoje autorizado a carregar a tag A01: CSRF (ausência de
# token sincronizador) e CORS (reflexão/curinga com credenciais). Qualquer achado novo
# tagueado A01 que não esteja aqui é, por definição, uma mudança de escopo — e precisa
# de decisão humana (ou é a mesma classe e a allowlist cresce, ou promete IDOR e a
# ferramenta ainda não tem base para isso).
_A01_PERMITIDOS = frozenset(
    {
        "COOKIE_SEM_SAMESITE",
        "COOKIE_SAMESITE_NONE_INSEGURO",
        "CORS_REFLEXAO_COM_CREDENCIAIS",
        "CORS_CURINGA_COM_CREDENCIAIS",
        "CORS_REFLEXAO_ORIGEM",
        "CORS_NULL_COM_CREDENCIAIS",
        "CSRF_TOKEN_AUSENTE",
    }
)

# Frases-chave (PT) que precisam aparecer, verbatim, em TODA cópia da declaração de
# escopo em português (código + metodologia + README).
_FRASES_PT = (
    "IDOR",
    "segmento numérico em path",
    "identidade via header/cookie",
    "múltiplas identidades autenticadas",
    "black-box",
)

# Mesmas frases-chave, na versão em inglês usada no README.en.md.
_FRASES_EN = (
    "IDOR",
    "numeric path segment",
    "identity via header/cookie",
    "authenticated identities",
    "black-box",
)


def test_a01_so_cobre_csrf_e_cors() -> None:
    """O conjunto REAL de achados A01 (lido de `_TAGS`, não de uma lista solta) é
    exatamente CSRF+CORS. Um achado A01 novo precisa tocar este teste de propósito."""
    a01_reais = frozenset(finding_id for finding_id, tag in _TAGS.items() if tag.owasp == A01)
    assert a01_reais == _A01_PERMITIDOS


def test_a01_escopo_declara_exclusao_de_idor_no_codigo() -> None:
    for frase in _FRASES_PT:
        assert frase in A01_ESCOPO, f"frase-chave {frase!r} ausente em mapping.A01_ESCOPO"


@pytest.mark.parametrize(
    ("arquivo", "frases"),
    [
        ("docs/metodologia.md", _FRASES_PT),
        ("README.md", _FRASES_PT),
        ("README.en.md", _FRASES_EN),
    ],
)
def test_declaracao_de_escopo_repetida_nos_documentos_publicos(
    arquivo: str, frases: tuple[str, ...]
) -> None:
    texto = (_RAIZ / arquivo).read_text(encoding="utf-8")
    ausentes = [frase for frase in frases if frase not in texto]
    assert ausentes == [], f"{arquivo} perdeu a(s) frase(s)-chave {ausentes}"
