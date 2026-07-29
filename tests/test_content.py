"""Testes da análise passiva de conteúdo HTML (mixed content, SRI, formulários)."""

from __future__ import annotations

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
