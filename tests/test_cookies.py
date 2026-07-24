"""Testes das flags de cookie."""

from __future__ import annotations

from conftest import make_context, make_probe, make_target
from sentinela.checks.cookies import CookiesChecker


def _run(set_cookies: tuple[str, ...], final_url: str = "https://example.com/"):
    probe = make_probe(set_cookies=set_cookies, final_url=final_url)
    ctx = make_context(primary=probe, target=make_target(final_url))
    return {f.id for f in CookiesChecker().run(ctx)}


def test_cookie_seguro_completo_nao_gera_achado() -> None:
    ids = _run(("sid=abc; Secure; HttpOnly; SameSite=Lax",))
    assert ids == set()


def test_cookie_sem_httponly_e_secure() -> None:
    ids = _run(("sid=abc; SameSite=Lax",))
    assert "COOKIE_SEM_HTTPONLY" in ids
    assert "COOKIE_SEM_SECURE" in ids


def test_cookie_sem_samesite() -> None:
    ids = _run(("sid=abc; Secure; HttpOnly",))
    assert "COOKIE_SEM_SAMESITE" in ids


def test_secure_nao_exigido_em_http() -> None:
    ids = _run(("sid=abc; HttpOnly; SameSite=Lax",), final_url="http://example.com/")
    assert "COOKIE_SEM_SECURE" not in ids


def test_sem_cookies_nao_gera_achado() -> None:
    assert _run(()) == set()


# Bateria de campo (2026-07-22): HttpOnly só é MEDIUM em cookie de sessão/auth.
# Cookie funcional (analytics/anti-abuso) sem HttpOnly é LOW, não MEDIUM (ex.: _octo do github.com).
def test_cookie_funcional_sem_httponly_e_low() -> None:
    ids = _run(("_ga=GA1.2.123; Secure; SameSite=Lax",))
    assert "COOKIE_SEM_HTTPONLY_FUNCIONAL" in ids
    assert "COOKIE_SEM_HTTPONLY" not in ids  # não é MEDIUM


def test_cookie_de_sessao_sem_httponly_continua_medium() -> None:
    ids = _run(("session_token=abc; Secure; SameSite=Lax",))
    assert "COOKIE_SEM_HTTPONLY" in ids


def test_samesite_none_sem_secure() -> None:
    ids = _run(("sid=abc; HttpOnly; SameSite=None",), final_url="http://example.com/")
    assert "COOKIE_SAMESITE_NONE_INSEGURO" in ids


def test_samesite_none_com_secure_ok() -> None:
    ids = _run(("sid=abc; Secure; HttpOnly; SameSite=None",))
    assert "COOKIE_SAMESITE_NONE_INSEGURO" not in ids


def test_prefixo_host_invalido() -> None:
    # __Host- exige Secure + Path=/ e sem Domain; aqui falta Secure
    ids = _run(("__Host-sid=abc; HttpOnly; SameSite=Lax; Path=/",))
    assert "COOKIE_PREFIXO_INVALIDO" in ids


def test_prefixo_host_valido_ok() -> None:
    ids = _run(("__Host-sid=abc; Secure; HttpOnly; SameSite=Lax; Path=/",))
    assert "COOKIE_PREFIXO_INVALIDO" not in ids


def test_prefixo_secure_sem_flag_secure() -> None:
    ids = _run(("__Secure-sid=abc; HttpOnly; SameSite=Lax",))
    assert "COOKIE_PREFIXO_INVALIDO" in ids
