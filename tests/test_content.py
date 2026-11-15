"""Testes da análise passiva de conteúdo HTML (mixed content, SRI, formulários)."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from conftest import make_context, make_probe, make_target
from sentinela.checks.content import ContentChecker


def _run(body: str, final_url: str = "https://example.com/") -> set[str]:
    probe = make_probe(body=body, final_url=final_url)
    ctx = make_context(primary=probe, target=make_target(final_url))
    return {f.id for f in ContentChecker().run(ctx)}


def test_pagina_limpa_nao_gera_achado() -> None:
    body = '<html><head><script src="/app.js"></script></head><body></body></html>'
    assert _run(body) == set()


def test_conteudo_misto() -> None:
    body = '<html><body><img src="http://cdn.exemplo.com/logo.png"></body></html>'
    assert "CONTEUDO_MISTO" in _run(body)


def test_sem_conteudo_misto_em_pagina_http() -> None:
    # página servida por HTTP: um recurso HTTP não é "conteúdo misto"
    assert "CONTEUDO_MISTO" not in _run('<img src="http://x.com/a.png">', final_url="http://example.com/")


def test_sri_ausente_em_terceiro() -> None:
    body = '<script src="https://cdn.terceiro.com/lib.js"></script>'
    assert "SRI_AUSENTE" in _run(body)


def test_sri_presente_nao_gera_achado() -> None:
    body = '<script src="https://cdn.terceiro.com/lib.js" integrity="sha384-abc" crossorigin></script>'
    assert "SRI_AUSENTE" not in _run(body)


def test_script_mesma_origem_nao_exige_sri() -> None:
    body = '<script src="https://example.com/app.js"></script>'
    assert "SRI_AUSENTE" not in _run(body)


def test_stylesheet_terceiro_sem_sri() -> None:
    body = '<link rel="stylesheet" href="https://fonts.terceiro.com/x.css">'
    assert "SRI_AUSENTE" in _run(body)


# Classe AUD0908-fp-sri-cdn-dinamico-fora-do-allowlist: SRI inviável não é "domínio
# Google" — é "loader de consentimento/tag-manager versionless de terceiro". A classe
# precisa reconhecer MÚLTIPLOS fornecedores concorrentes, não só o caso de campo que
# originou o item (Google), senão é o mesmo defeito com outro nome.
def test_loader_google_tag_manager_e_sri_inviavel_nao_sri_ausente() -> None:
    body = '<script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script>'
    achados = _run(body)
    assert "SRI_INVIAVEL_TERCEIRO_DINAMICO" in achados
    assert "SRI_AUSENTE" not in achados


def test_loader_cookiebot_de_fornecedor_concorrente_tambem_e_sri_inviavel() -> None:
    """A classe não pode ser um allowlist só-Google: outro fornecedor, mesmo padrão."""
    body = '<script src="https://consent.cookiebot.com/uc.js?cbid=abc-123"></script>'
    achados = _run(body)
    assert "SRI_INVIAVEL_TERCEIRO_DINAMICO" in achados
    assert "SRI_AUSENTE" not in achados


def test_loader_onetrust_tambem_e_sri_inviavel() -> None:
    body = '<script src="https://cdn.cookielaw.org/consent/abc/OtAutoBlock.js"></script>'
    achados = _run(body)
    assert "SRI_INVIAVEL_TERCEIRO_DINAMICO" in achados
    assert "SRI_AUSENTE" not in achados


def test_biblioteca_terceiro_com_versao_no_caminho_continua_sri_ausente() -> None:
    """Caminho VERSIONADO (o fornecedor pode fixar hash) não é a classe inviável —
    mesmo contendo uma palavra da lista, como 'cmp' num nome de pacote qualquer."""
    body = '<script src="https://cdn.terceiro.com/libs/cmp-sdk-2.3.1.min.js"></script>'
    achados = _run(body)
    assert "SRI_AUSENTE" in achados
    assert "SRI_INVIAVEL_TERCEIRO_DINAMICO" not in achados


def test_script_terceiro_generico_sem_palavra_da_classe_continua_sri_ausente() -> None:
    body = '<script src="https://cdn.terceiro.com/lib.js"></script>'
    achados = _run(body)
    assert "SRI_AUSENTE" in achados
    assert "SRI_INVIAVEL_TERCEIRO_DINAMICO" not in achados


# INVARIANTE (a classe, não o exemplo): para QUALQUER um dos fornecedores conhecidos
# de loader de consentimento/tag-manager, um caminho SEM versão sempre vira o achado
# fraco (SRI_INVIAVEL_TERCEIRO_DINAMICO), nunca o forte (SRI_AUSENTE) — e isso vale
# para a lista inteira de fornecedores, não só para o caso de campo (Google).
_PALAVRAS_LOADER_DINAMICO = (
    "gtag",
    "gtm",
    "tagmanager",
    "consent",
    "cookiebot",
    "onetrust",
    "otsdkstub",
    "otautoblock",
    "cmp",
    "tcf",
    "cookieconsent",
    "usercentrics",
    "didomi",
    "quantcast",
    "trustarc",
    "cookieyes",
    "iubenda",
)


@settings(max_examples=200)
@given(palavra=st.sampled_from(_PALAVRAS_LOADER_DINAMICO), sufixo=st.sampled_from(("js", "php")))
def test_invariante_palavra_da_classe_sem_versao_sempre_e_inviavel(palavra: str, sufixo: str) -> None:
    body = f'<script src="https://cdn.fornecedor-{palavra}.example/{palavra}.{sufixo}"></script>'
    achados = _run(body)
    assert "SRI_INVIAVEL_TERCEIRO_DINAMICO" in achados, f"não reconheceu a classe para {palavra!r}"
    assert "SRI_AUSENTE" not in achados


@settings(max_examples=200)
@given(
    palavra=st.sampled_from(_PALAVRAS_LOADER_DINAMICO),
    major=st.integers(min_value=0, max_value=99),
    minor=st.integers(min_value=0, max_value=99),
)
def test_invariante_versao_no_caminho_volta_a_ser_sri_ausente(palavra: str, major: int, minor: int) -> None:
    """Espelho da invariante: havendo versão no próprio caminho, SRI volta a ser
    viável — a classe "inviável" nunca mascara um recurso que o fornecedor versiona."""
    body = f'<script src="https://cdn.fornecedor-{palavra}.example/{palavra}-{major}.{minor}.js"></script>'
    achados = _run(body)
    assert "SRI_AUSENTE" in achados
    assert "SRI_INVIAVEL_TERCEIRO_DINAMICO" not in achados


def test_form_action_insegura() -> None:
    body = '<form action="http://example.com/login" method="post"></form>'
    assert "FORM_ACTION_INSEGURA" in _run(body)


def test_senha_sobre_http() -> None:
    body = '<form><input type="password" name="pw"></form>'
    assert "SENHA_SEM_HTTPS" in _run(body, final_url="http://example.com/")


def test_senha_sobre_https_nao_gera_achado() -> None:
    body = '<form><input type="password" name="pw"></form>'
    assert "SENHA_SEM_HTTPS" not in _run(body)


def test_corpo_vazio_nao_gera_achado() -> None:
    assert _run("") == set()


def _run_headers(body: str, headers: dict[str, str]) -> set[str]:
    probe = make_probe(body=body, headers=headers, final_url="https://example.com/")
    ctx = make_context(primary=probe, target=make_target("https://example.com/"))
    return {f.id for f in ContentChecker().run(ctx)}


def test_cache_sensivel_sem_nostore() -> None:
    ids = _run_headers('<form><input type="password" name="pw"></form>', {})
    assert "CACHE_SENSIVEL_SEM_NOSTORE" in ids


def test_cache_sensivel_com_nostore_ok() -> None:
    ids = _run_headers('<form><input type="password" name="pw"></form>', {"Cache-Control": "no-store"})
    assert "CACHE_SENSIVEL_SEM_NOSTORE" not in ids


def test_cache_sem_senha_nao_gera_achado() -> None:
    ids = _run_headers("<html><body>página comum</body></html>", {})
    assert "CACHE_SENSIVEL_SEM_NOSTORE" not in ids


# --------------------------------------------------------------------------- #
# Orçamento de CPU contra alvo hostil. O modelo de ameaça da ferramenta é literalmente
# "apontar para um alvo que pode não querer ser auditado". Um corpo de 256 KB (o teto
# exato que o motor garante entregar) SEM nenhum `>` fazia cada `<script ` varrer até o
# fim da string: O(n²), ~84 s de CPU medidos e ZERO achados — o operador não vê erro,
# vê lentidão. O teto de 2048 caracteres por tag torna a busca linear.
# --------------------------------------------------------------------------- #
def test_corpo_hostil_de_256kb_nao_estoura_o_orcamento_de_cpu() -> None:
    import time

    from sentinela.core.engine import _PRIMARY_BODY_CAP

    corpo = "<script " * (_PRIMARY_BODY_CAP // 8)
    assert len(corpo) == _PRIMARY_BODY_CAP  # o payload é exatamente o teto do motor
    inicio = time.perf_counter()
    achados = _run(corpo)
    decorrido = time.perf_counter() - inicio
    assert achados == set()
    assert decorrido < 3.0, f"ContentChecker levou {decorrido:.1f}s num corpo hostil de 256 KB"


def test_menor_que_o_teto_de_atributos_continua_sendo_detectado() -> None:
    # O teto não pode virar falso negativo em HTML legítimo com muitos atributos —
    # inclusive com `<` DENTRO de valor de atributo, que é HTML válido e comum.
    body = (
        '<img alt="1 < 2" src="http://inseguro.tld/pixel.gif">'
        '<script onload="if(a<b)f()" src="http://inseguro.tld/x.js"></script>'
    )
    assert "CONTEUDO_MISTO" in _run(body)
