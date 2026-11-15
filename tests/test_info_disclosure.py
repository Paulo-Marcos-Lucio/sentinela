"""Testes de exposição de informação (não-intrusiva).

A classe de FP corrigida aqui (auditoria FN/FP 2026-09-08): a antiga condição só
exigia o token de versão (`\\d+\\.\\d+`) no valor do cabeçalho `Server` — qualquer
OUTRO cabeçalho da lista (`X-Powered-By`, `X-Generator`, ...) virava
`VERSAO_STACK_EXPOSTA`, com o impacto afirmando "CVEs daquela versão específica",
mesmo quando só o NOME do produto tinha vazado, sem nenhuma versão. O teste de
propriedade abaixo tranca a classe: para qualquer cabeçalho da lista e qualquer
valor, só existe achado de versão exposta quando um token de versão está
realmente presente, e o achado de "sem versão" nunca carrega a promessa de CVE
por versão.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from conftest import make_context, make_probe
from sentinela.checks.info_disclosure import _LEAK_HEADERS, _VERSION_RE, InfoDisclosureChecker


def _run(headers=None, body=""):
    probe = make_probe(headers=headers or {}, body=body)
    return list(InfoDisclosureChecker().run(make_context(primary=probe)))


def _ids(headers=None, body=""):
    return {f.id for f in _run(headers=headers, body=body)}


def test_versao_servidor_exposta() -> None:
    assert "VERSAO_STACK_EXPOSTA" in _ids(headers={"Server": "nginx/1.18.0"})


def test_x_powered_by_exposto() -> None:
    assert "VERSAO_STACK_EXPOSTA" in _ids(headers={"X-Powered-By": "PHP/7.4.3"})


def test_server_generico_sem_versao_nao_afirma_versao() -> None:
    achados = _ids(headers={"Server": "cloudflare"})
    assert "VERSAO_STACK_EXPOSTA" not in achados
    assert "TECNOLOGIA_DIVULGADA_SEM_VERSAO" in achados


def test_x_powered_by_sem_versao_nao_afirma_versao() -> None:
    """Era exatamente o FP: nome sem versão em cabeçalho != Server virava "versão exposta"."""
    achados = _ids(headers={"X-Powered-By": "PHP"})
    assert "VERSAO_STACK_EXPOSTA" not in achados
    assert "TECNOLOGIA_DIVULGADA_SEM_VERSAO" in achados


def test_listagem_diretorio() -> None:
    body = "<html><head><title>Index of /uploads</title></head><body>Index of /</body></html>"
    assert "LISTAGEM_DIRETORIO" in _ids(body=body)


# Valores de cabeçalho com e sem token de versão, cobrindo os quatro cabeçalhos
# da lista de vazamento (não só Server).
_valores_sem_versao = st.text(alphabet=st.characters(blacklist_categories=("Cc", "Cs")), min_size=1).filter(
    lambda s: not _VERSION_RE.search(s)
)
_valores_com_versao = st.builds(
    lambda nome, maior, menor: f"{nome}/{maior}.{menor}",
    st.sampled_from(("nginx", "Apache", "PHP", "ASP.NET", "Express")),
    st.integers(min_value=0, max_value=99),
    st.integers(min_value=0, max_value=99),
)


# A afirmação que só pode valer quando um número de versão foi mesmo visto.
_AFIRMACAO_CVE_POR_VERSAO = "mapear vulnerabilidades conhecidas (CVEs) daquela versão específica"


@settings(max_examples=200)
@given(header=st.sampled_from(_LEAK_HEADERS), valor=_valores_sem_versao)
def test_invariante_sem_token_de_versao_nunca_afirma_versao_exposta(header: str, valor: str) -> None:
    """INVARIANTE (a classe do FP): sem `\\d+\\.\\d+` no valor, NUNCA sai VERSAO_STACK_EXPOSTA —
    para qualquer um dos cabeçalhos da lista, não só Server — e nenhum achado gerado
    afirma a capacidade de mapear CVE de uma versão que não foi vista."""
    achados = _run(headers={header: valor})
    ids = {f.id for f in achados}
    assert "VERSAO_STACK_EXPOSTA" not in ids
    for achado in achados:
        assert _AFIRMACAO_CVE_POR_VERSAO not in achado.impact


@settings(max_examples=200)
@given(header=st.sampled_from(_LEAK_HEADERS), valor=_valores_com_versao)
def test_invariante_com_token_de_versao_sempre_afirma_versao_exposta(header: str, valor: str) -> None:
    """Espelho da invariante: havendo token de versão, o achado é sempre o de versão
    exposta (nunca cai silenciosamente no achado mais fraco de "sem versão")."""
    ids = _ids(headers={header: valor})
    assert "VERSAO_STACK_EXPOSTA" in ids
    assert "TECNOLOGIA_DIVULGADA_SEM_VERSAO" not in ids
