"""Testes do checker de superfície de formulários e injeção (`forms`).

Cada teste ancora um comportamento EXATO: falha se a detecção for removida (anti-fachada)
e falha se um falso positivo for introduzido. A fronteira passivo↔ativo é parte do
contrato — o checker sinaliza superfície, nunca afirma exploração.
"""

from __future__ import annotations

from collections.abc import Iterable

from sentinela.checks.forms import FormsChecker
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
