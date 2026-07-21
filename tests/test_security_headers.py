"""Testes do analisador de cabeçalhos de segurança."""

from __future__ import annotations

from conftest import make_context, make_probe, make_target
from sentinela.checks.security_headers import SecurityHeadersChecker

# Um conjunto de cabeçalhos considerado "bom o suficiente" para não gerar achados fortes.
BONS_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def _run(headers: dict[str, str]):
    probe = make_probe(headers=headers)
    return list(SecurityHeadersChecker().run(make_context(primary=probe)))


def test_todos_bons_nao_geram_achados() -> None:
    ids = {f.id for f in _run(BONS_HEADERS)}
    assert ids == set()


def test_csp_ausente() -> None:
    headers = dict(BONS_HEADERS)
    del headers["Content-Security-Policy"]
    ids = {f.id for f in _run(headers)}
    assert "CSP_AUSENTE" in ids


def test_hsts_ausente_em_https() -> None:
    headers = dict(BONS_HEADERS)
    del headers["Strict-Transport-Security"]
    ids = {f.id for f in _run(headers)}
    assert "HSTS_AUSENTE" in ids


def test_hsts_nao_avaliado_em_http() -> None:
    probe = make_probe(headers={}, final_url="http://example.com/")
    ctx = make_context(primary=probe, target=make_target("http://example.com/"))
    ids = {f.id for f in SecurityHeadersChecker().run(ctx)}
    assert "HSTS_AUSENTE" not in ids


def test_clickjacking_detectado_sem_xfo_nem_frame_ancestors() -> None:
    headers = {"Content-Security-Policy": "default-src 'self'"}  # sem frame-ancestors, sem XFO
    ids = {f.id for f in _run(headers)}
    assert "CLICKJACKING_SEM_PROTECAO" in ids


def test_csp_unsafe_inline_gera_achado() -> None:
    headers = dict(BONS_HEADERS)
    headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    ids = {f.id for f in _run(headers)}
    assert "CSP_DIRETIVA_INSEGURA" in ids


def test_xxss_protection_legado() -> None:
    headers = dict(BONS_HEADERS)
    headers["X-XSS-Protection"] = "1; mode=block"
    ids = {f.id for f in _run(headers)}
    assert "XXSS_PROTECTION_LEGADO" in ids


def test_probe_com_erro_nao_gera_achados() -> None:
    probe = make_probe(error="ConnectError")
    assert list(SecurityHeadersChecker().run(make_context(primary=probe))) == []
