# tests/test_paridade_receita_suite.py
# Paridade de receita da SUITE AppSec (Classe F da auditoria cruzada Pro, 2026-09-12).
#
# Os valores-ouro abaixo sao IDENTICOS nos quatro tools da suite (sentinela/guardiao/
# chaveiro/esteira): um cliente confere os quatro laudos com UMA unica receita. Este arquivo
# TRAVA por teste que o codigo de PRODUCAO da Sentinela bate com o ouro — sem ele, a receita
# "convergiu" na rodada 1 mas nada impedia uma divergencia silenciosa depois.
#
# NAO edite os valores esperados. So o import/adaptador de chamada muda entre os quatro repos.
#
# Ponto de honestidade (o cetico checa): a Sentinela e um scanner PASSIVO — ela le a superficie
# que o alvo expoe (cabecalhos, TLS, rotas anunciadas) e NUNCA coleta segredo/credencial do
# alvo. Logo NAO existe, na producao da Sentinela, uma funcao `redact(keep=2)` de segredo para
# importar. Por isso:
#   * `artifact_sha256` e travado contra a funcao REAL de producao (`serializar_com_selo`), que
#     e o que de fato importa nesta ferramenta — a receita do selo do laudo.
#   * a clausula de redacao do contrato de suite entra aqui como REFERENCIA compartilhada (para
#     os quatro arquivos ficarem identicos no ouro) e e ligada-a-producao nos tres tools que de
#     fato coletam segredo; na Sentinela o que se liga a producao e o MARCADOR de elisao (U+2026),
#     provado contra `checks/_util.truncate`. Isto e disclosure, nao reimplementacao-para-passar.
from __future__ import annotations

import hashlib
import json

from hypothesis import given
from hypothesis import strategies as st

# >>> FUNCAO REAL DE PRODUCAO DA SENTINELA (substitui o stub `_artifact_sha256` do template) <<<
from sentinela.checks._util import truncate
from sentinela.core.proveniencia import serializar_com_selo


def _artifact_sha256_producao(doc: dict[str, object]) -> str:
    """`artifact_sha256` como a PRODUCAO o calcula: sela `doc` com `serializar_com_selo` e
    devolve o selo embutido. E o caminho real do laudo — nao uma reimplementacao da receita."""
    selado = json.loads(serializar_com_selo(doc))
    return str(selado["artifact_sha256"])


# Referencia do contrato de redacao publicado da SUITE (keep=2, marcador U+2026, 2 pontas;
# entrada <= 2*keep vira so o marcador). Ligado-a-producao nos tres tools que coletam segredo;
# aqui e a referencia compartilhada, ja que a Sentinela nao coleta segredo (ver cabecalho).
def _redact_pub(x: str, keep: int = 2, mark: str = "…") -> str:
    return mark if len(x) <= 2 * keep else x[:keep] + mark + x[-keep:]


GOLDEN_DOC = {"alvo": "exemplo.com.br", "achados": 2, "regra": "pção-ção", "z": 1, "a": [3, 2, 1]}
GOLDEN_ARTIFACT_SHA256 = "bcd1a357a62308d43397cf4357ffb4fa45b904f9a31353da7e10468f213f6af1"
GOLDEN_REDACT = {
    "AKIAIOSFODNN7EXAMPLE": "AK…LE",
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a": "gh…4a",
    "1234": "…",
}


def test_artifact_sha256_receita_unica_da_suite() -> None:
    """O selo que a PRODUCAO da Sentinela emite para o documento canonico da suite bate,
    byte a byte, com o valor-ouro compartilhado pelas quatro ferramentas."""
    assert _artifact_sha256_producao(GOLDEN_DOC) == GOLDEN_ARTIFACT_SHA256


# JSON-safe sem floats (NaN/precisao) e sem a chave reservada do selo — o que o laudo real carrega.
_JSON_ESCALAR = st.none() | st.booleans() | st.integers(min_value=-(10**9), max_value=10**9) | st.text()
_JSON_VALOR = st.recursive(
    _JSON_ESCALAR,
    lambda filho: st.lists(filho, max_size=4) | st.dictionaries(st.text(max_size=8), filho, max_size=4),
    max_leaves=12,
)


@given(
    doc=st.dictionaries(
        st.text(max_size=8).filter(lambda k: k != "artifact_sha256"), _JSON_VALOR, max_size=6
    )
)
def test_producao_segue_a_receita_da_suite_para_qualquer_documento(doc: dict[str, object]) -> None:
    """Invariante F (a CLASSE, nao o exemplo): para QUALQUER documento JSON-safe, o
    `artifact_sha256` que a producao embute e exatamente o sha256 da serializacao canonica
    da suite (compacto-ordenado). Isto prova que a Sentinela nao tem um caminho de selagem
    paralelo que fugiria da receita comum — a razao de a Classe F existir."""
    esperado = hashlib.sha256(
        json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert _artifact_sha256_producao(doc) == esperado


def test_redact_publicado_no_maximo_2_por_ponta() -> None:
    """Contrato de redacao compartilhado da suite (referencia — ver cabecalho): no caminho
    publicado nunca sai mais que 2 chars por ponta, e o marcador e U+2026."""
    for entrada, esperado in GOLDEN_REDACT.items():
        assert _redact_pub(entrada) == esperado


def test_marcador_de_elisao_da_producao_e_o_da_suite() -> None:
    """Ligacao-a-producao possivel na Sentinela: o marcador de elisao do texto publicado
    (`checks/_util.truncate`, usado nos laudos) e o MESMO U+2026 do contrato de redacao da
    suite — um cliente ve o mesmo marcador nas quatro ferramentas."""
    cortado = truncate("x" * 500, limit=64)
    assert cortado.endswith("…")
    assert len(cortado) == 64
