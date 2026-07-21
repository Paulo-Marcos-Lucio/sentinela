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
