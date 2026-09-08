"""Testes do checker de superfície de formulários e injeção (`forms`).

Cada teste ancora um comportamento EXATO: falha se a detecção for removida (anti-fachada)
e falha se um falso positivo for introduzido. A fronteira passivo↔ativo é parte do
contrato — o checker sinaliza superfície, nunca afirma exploração.
"""

from __future__ import annotations

import time
from collections.abc import Iterable

from sentinela.checks.forms import FormsChecker, _coletar_forms
from sentinela.core.config import ScanConfig
from sentinela.core.context import ScanContext
from sentinela.core.http import Probe
from sentinela.core.models import Finding, Target
from sentinela.knowledge import mapping


def _ids(url: str, body: str) -> set[str]:
    scheme = url.split("://", 1)[0]
    target = Target(raw=url, scheme=scheme, host="alvo", port=80 if scheme == "http" else 443, url=url)
    probe = Probe(url=url, status_code=200, headers={}, body_snippet=body, final_url=url)
    ctx = ScanContext(target=target, client=None, config=ScanConfig(), primary=probe)  # type: ignore[arg-type]
    achados: Iterable[Finding] = FormsChecker().run(ctx)
    return {f.id for f in achados}


# --- detecções (falham se a correção for desfeita) ------------------------- #


def test_senha_em_formulario_get_e_detectada() -> None:
    ids = _ids(
        "http://a/login",
        '<form method="get" action="/login"><input name="senha" type="password"></form>',
    )
    assert "SENHA_EM_GET" in ids


def test_formulario_https_postando_para_http_e_conteudo_misto() -> None:
    # Página segura, mas o form envia a senha para http:// — caso que o checker de
    # conteúdo (SENHA_SEM_HTTPS, só página inteira em HTTP) NÃO cobre.
    ids = _ids(
        "https://a/login",
        '<form method="post" action="http://a/login"><input type="password" name="p"></form>',
    )
    assert "FORMULARIO_CREDENCIAL_SEM_HTTPS" in ids


def test_credencial_em_pagina_http_nao_duplica_senha_sem_https() -> None:
    # Página HTTP com form de action relativo: o `forms` NÃO reporta (evita penalidade
    # dupla com SENHA_SEM_HTTPS, que é do checker de conteúdo).
    ids = _ids(
        "http://a/login",
        '<form method="post" action="/login"><input type="password" name="p"></form>',
    )
    assert "FORMULARIO_CREDENCIAL_SEM_HTTPS" not in ids


def test_formulario_post_sem_token_anti_csrf_e_detectado() -> None:
    ids = _ids("https://a/comentar", '<form method="post" action="/c"><input name="txt"></form>')
    assert "CSRF_TOKEN_AUSENTE" in ids


def test_parametro_refletido_sem_escape_e_superficie_de_xss() -> None:
    ids = _ids("https://a/eco?nome=<svg/onload=alert(1)>", "<h1>Ola, <svg/onload=alert(1)></h1>")
    assert "REFLEXAO_DE_PARAMETRO" in ids


def test_dado_sensivel_na_query_string_e_detectado() -> None:
    ids = _ids("https://a/cb?access_token=Zm9vYmFyYmF6cXV4", "<html>ok</html>")
    assert "DADO_SENSIVEL_NA_URL" in ids


# --- ausência de falso positivo (falham se o checker ficar barulhento) ----- #


def test_formulario_post_com_token_csrf_e_https_nao_gera_achado() -> None:
    ids = _ids(
        "https://a/login",
        '<form method="post" action="/login">'
        '<input type="password" name="senha">'
        '<input type="hidden" name="csrf_token" value="x"></form>',
    )
    assert ids == set()


def test_formulario_get_de_busca_sem_senha_nao_exige_csrf() -> None:
    # Form GET de busca não muda estado; exigir token seria falso positivo.
    ids = _ids("https://a/busca", '<form method="get" action="/busca"><input name="q"></form>')
    assert "CSRF_TOKEN_AUSENTE" not in ids
    assert "SENHA_EM_GET" not in ids


def test_reflexao_com_escape_nao_e_sinalizada() -> None:
    # O servidor escapou a saída: não é superfície de XSS.
    ids = _ids("https://a/eco?nome=<svg>", "<h1>Ola, &lt;svg&gt;</h1>")
    assert "REFLEXAO_DE_PARAMETRO" not in ids


def test_valor_curto_nao_dispara_reflexao_por_acaso() -> None:
    # 'ok' tem 2 chars e casa em qualquer HTML — não pode virar achado.
    ids = _ids("https://a/p?x=ok", "<html><body>ok</body></html>")
    assert "REFLEXAO_DE_PARAMETRO" not in ids


def test_pagina_limpa_nao_gera_achado() -> None:
    assert _ids("https://a/", "<html><body><h1>bem-vindo</h1></body></html>") == set()


# --- contrato de taxonomia (todo achado novo tem OWASP 2025 + CWE) --------- #


def test_todo_achado_do_checker_tem_owasp_e_cwe_mapeados() -> None:
    for finding_id in (
        "SENHA_EM_GET",
        "FORMULARIO_CREDENCIAL_SEM_HTTPS",
        "CSRF_TOKEN_AUSENTE",
        "REFLEXAO_DE_PARAMETRO",
        "DADO_SENSIVEL_NA_URL",
    ):
        tag = mapping.tag_for(finding_id)
        assert tag is not None, finding_id
        assert tag.owasp is not None and ":2025" in tag.owasp
        assert tag.cwe is not None and tag.cwe.startswith("CWE-")


def test_checker_registrado_no_pipeline() -> None:
    from sentinela.core.registry import ALL_CHECKERS

    assert FormsChecker in ALL_CHECKERS
    assert FormsChecker.intrusive is False  # é passivo: entra sempre, sem gating


def test_corpo_hostil_nao_trava_a_varredura() -> None:
    # DoS: um `<script` de 256 KB sem fechar travava o HTMLParser (>120 s), a mesma
    # classe do ReDoS que o F100 matou em content.py. A extração por regex limitada
    # tem que resolver em tempo trivial. Cronometrado — a regressão volta VERMELHA.
    hostil = "<script " + "a" * 262_144
    inicio = time.perf_counter()
    forms = _coletar_forms(hostil)
    decorrido = time.perf_counter() - inicio
    assert forms == []  # sem `<form`, nada a extrair
    assert decorrido < 1.0, f"extração de forms degradou: {decorrido:.2f}s"


def test_corpo_hostil_com_form_valido_ainda_e_lido_rapido() -> None:
    # Ruído hostil ANTES de um form legítimo: o form real ainda é lido, sem travar.
    corpo = (
        "<script " + "a" * 200_000 + "</script>" + "<form method='post' action='/x'><input name='c'></form>"
    )
    inicio = time.perf_counter()
    forms = _coletar_forms(corpo)
    decorrido = time.perf_counter() - inicio
    assert decorrido < 1.0, f"degradou com ruído + form: {decorrido:.2f}s"
    assert any(f.method == "post" for f in forms)


# =========================================================================== #
# Auditoria 2026-09-08 — invariantes de correção (atacam a CLASSE, não o exemplo).
# =========================================================================== #
from hypothesis import given  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from sentinela.checks.forms import (  # noqa: E402
    _A_HANDLER_JS,
    _CSRF,
    _tem_token_credencial,
    _tem_token_lgpd,
)
from sentinela.core.models import Severity  # noqa: E402


def _findings(url: str, body: str) -> list[Finding]:
    scheme = url.split("://", 1)[0]
    target = Target(raw=url, scheme=scheme, host="alvo", port=80 if scheme == "http" else 443, url=url)
    probe = Probe(url=url, status_code=200, headers={}, body_snippet=body, final_url=url)
    ctx = ScanContext(target=target, client=None, config=ScanConfig(), primary=probe)  # type: ignore[arg-type]
    return list(FormsChecker().run(ctx))


# --- Classe 1: fp-sensivel-substring-credencial --------------------------- #
# INVARIANTE: casa por TOKEN inteiro do nome, nunca por substring solta.
def test_credencial_casa_por_token_inteiro_nao_por_substring() -> None:
    # substrings que NÃO podem casar (eram os FP)
    for nome in (
        "author",
        "co-author",
        "comment_author_email",
        "wildcard",
        "cardholder",
        "cardapio",
        "discard",
        "sessionStorage",
        "tokenized",
    ):
        assert not _tem_token_credencial(nome), nome
        assert not _tem_token_lgpd(nome), nome
    # tokens inteiros de credencial que DEVEM casar (o lado que não pode afrouxar)
    for nome in (
        "senha",
        "password",
        "access_token",
        "api_key",
        "api-key",
        "apikey",
        "auth",
        "cvv",
        "card",
        "cartão",
        "user[secret]",
    ):
        assert _tem_token_credencial(nome), nome


def test_cpf_cnpj_sao_lgpd_e_nunca_credencial() -> None:
    for nome in ("cpf", "cnpj", "cliente_cpf", "cpfCnpj"):
        assert _tem_token_lgpd(nome), nome
        assert not _tem_token_credencial(nome), nome


@given(
    tok=st.sampled_from(sorted({"senha", "password", "token", "auth", "card", "cvv", "secret"})),
    pre=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=6),
    suf=st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=6),
)
def test_property_token_no_meio_de_palavra_nao_casa_mas_delimitado_casa(
    tok: str, pre: str, suf: str
) -> None:
    # colado dentro de uma palavra maior -> NÃO é o token -> não casa
    assert not _tem_token_credencial(pre + tok + suf)
    # o mesmo token delimitado (separadores/camelCase) -> É token inteiro -> casa
    assert _tem_token_credencial(f"{pre}_{tok}_{suf}")
    assert _tem_token_credencial(f"{pre}[{tok}]")


def test_credencial_na_url_e_alta_dado_pessoal_e_media() -> None:
    cred = {
        f.id: f.severity for f in _findings("https://a/cb?access_token=Zm9vYmFyYmF6", "<html>ok</html>")
    }
    assert cred.get("DADO_SENSIVEL_NA_URL") is Severity.HIGH
    assert "DADO_PESSOAL_NA_URL" not in cred
    pess = {f.id: f.severity for f in _findings("https://a/cb?cpf=12345678900", "<html>ok</html>")}
    assert pess.get("DADO_PESSOAL_NA_URL") is Severity.MEDIUM
    assert "DADO_SENSIVEL_NA_URL" not in pess


def test_param_com_substring_credencial_nao_gera_achado_de_url() -> None:
    # `?author=` e `?discard=` não podem mais disparar credencial/dado-pessoal na URL.
    ids = _ids("https://a/busca?author=machado&discard=1", "<html>ok</html>")
    assert "DADO_SENSIVEL_NA_URL" not in ids
    assert "DADO_PESSOAL_NA_URL" not in ids


# --- Classe 4: forms-senha-em-get-spa ------------------------------------- #
# INVARIANTE: handler de framework (onSubmit/@submit.prevent/(ngSubmit)/v-on:submit) é
# interceptação por JS -> NÃO submete pela URL.
def test_handler_de_framework_isenta_senha_em_get() -> None:
    for header in (
        '@submit.prevent="login"',
        '(ngSubmit)="login()"',
        'v-on:submit.prevent="x"',
        "onSubmit={login}",
    ):
        html = f'<form {header}><input type="password" name="p"><button>Ok</button></form>'
        assert "SENHA_EM_GET" not in _ids("https://a/login", html), header


def test_get_nativo_com_senha_ainda_dispara_apos_a_correcao() -> None:
    # O lado que não pode afrouxar: GET nativo de verdade continua vazando credencial na URL.
    assert "SENHA_EM_GET" in _ids(
        "https://a/login", '<form method="get" action="/login"><input type="password" name="p"></form>'
    )
    assert "SENHA_EM_GET" in _ids(
        "https://a/login",
        '<form action="/login"><input type="password" name="p"><button>Entrar</button></form>',
    )


def test_regex_handler_reconhece_todas_as_sintaxes_de_framework() -> None:
    for h in ("onsubmit=", "onSubmit={f}", "@submit=", "@submit.prevent=", "v-on:submit=", "(ngSubmit)="):
        assert _A_HANDLER_JS.search(h), h
    # não pode casar um atributo qualquer que só CONTENHA 'submit'
    assert not _A_HANDLER_JS.search('data-submitkind="x"')


# --- Classe 5: fp-csrf-nonce-nao-reconhecido ------------------------------ #
def test_nonce_e_reconhecido_como_token_anti_csrf() -> None:
    for nome in ("_wpnonce", "wpnonce", "nonce"):
        assert _CSRF.search(nome), nome
    html = '<form method="post" action="/subscribe"><input type="hidden" name="_wpnonce" value="x"></form>'
    assert "CSRF_TOKEN_AUSENTE" not in _ids("https://a/subscribe", html)


def test_post_sem_token_algum_ainda_exige_csrf() -> None:
    # O lado oposto: um POST sem NENHUM token reconhecido continua sendo achado real.
    html = '<form method="post" action="/c"><input name="txt"></form>'
    assert "CSRF_TOKEN_AUSENTE" in _ids("https://a/c", html)
