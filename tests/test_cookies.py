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


# --------------------------------------------------------------------------- #
# Cookie de CSRF no padrão double-submit. Laravel/Axios, Angular, Django e csurf
# entregam esse cookie legível por JS POR DESIGN — o JS precisa copiar o valor no
# cabeçalho. Marcá-lo MÉDIA com o impacto "um XSS rouba a sessão" é duplamente
# falso (não é sessão, e HttpOnly ali quebra a aplicação) e é o achado que o dev
# do cliente refuta na reunião, levando junto a credibilidade dos corretos.
# --------------------------------------------------------------------------- #
def test_cookie_de_csrf_e_informativo_nao_medio() -> None:
    for nome in ("XSRF-TOKEN", "csrftoken", "_csrf"):
        ids = _run((f"{nome}=abc; Secure; SameSite=Lax",))
        assert ids == {"COOKIE_CSRF_LEGIVEL_POR_JS"}, f"{nome} -> {ids}"


def test_cookie_de_csrf_nao_apaga_o_achado_de_sessao_no_mesmo_site() -> None:
    ids = _run(("XSRF-TOKEN=abc; Secure; SameSite=Lax", "PHPSESSID=x; Secure; SameSite=Lax"))
    assert {"COOKIE_CSRF_LEGIVEL_POR_JS", "COOKIE_SEM_HTTPONLY"} <= ids


def test_cookie_de_csrf_sem_secure_continua_sendo_achado_real() -> None:
    # Sem Secure, o atacante na rede SOBRESCREVE o token (cookie tossing) e o
    # double-submit passa a validar um valor escolhido por ele. Isto não é rebaixado.
    ids = _run(("XSRF-TOKEN=abc; SameSite=Lax",))
    assert "COOKIE_SEM_SECURE" in ids


def test_cookie_de_sessao_com_csrf_no_nome_continua_medio() -> None:
    # Desempate: `csrf_session_id` é sessão, não token de CSRF.
    ids = _run(("csrf_session_id=abc; Secure; SameSite=Lax",))
    assert "COOKIE_SEM_HTTPONLY" in ids
    assert "COOKIE_CSRF_LEGIVEL_POR_JS" not in ids


def test_access_token_continua_medio() -> None:
    ids = _run(("access_token=abc; Secure; SameSite=Lax",))
    assert "COOKIE_SEM_HTTPONLY" in ids


# =========================================================================== #
# Classe cookies-analytics-session-classificado-auth (auditoria 2026-09-08).
# INVARIANTE: id de sessão de ANALYTICS/telemetria não é sessão de AUTENTICAÇÃO.
# =========================================================================== #
from sentinela.checks.cookies import _e_telemetria, _is_session_like  # noqa: E402


def test_cookie_de_telemetria_nao_e_sessao_de_autenticacao() -> None:
    # Nomes de analytics/telemetria — mesmo trazendo 'session'/'identity' e valor opaco.
    casos = [
        ("_mldataSessionId", ""),
        ("amplitude-session-id", ""),
        ("visitor_session_id", ""),
        ("kndctr_ABC123_AdobeOrg_identity", "aGVsbG9vcGFxdWVibG9i9f3c8d2e1a"),
    ]
    for nome, valor in casos:
        assert _e_telemetria(nome), nome
        assert not _is_session_like(nome, valor), nome


def test_sessao_de_autenticacao_real_continua_sendo_sessao() -> None:
    # O lado que NÃO pode afrouxar: sessões reais continuam classificadas como auth.
    for nome, valor in [
        ("JSESSIONID", "x"),
        ("session_token", "x"),
        ("access_token", "x"),
        ("PHPSESSID", "x"),
    ]:
        assert not _e_telemetria(nome), nome
        assert _is_session_like(nome, valor), nome


def test_analytics_sem_httponly_e_low_nao_medium() -> None:
    # Cookie de telemetria sem HttpOnly cai no balde funcional (BAIXA), não em auth (MÉDIA).
    ids = _run(("kndctr_ABC_AdobeOrg_identity=blob9f3c8d2e1a4b; Secure; SameSite=Lax",))
    assert "COOKIE_SEM_HTTPONLY_FUNCIONAL" in ids
    assert "COOKIE_SEM_HTTPONLY" not in ids


def test_analytics_nao_engole_o_achado_funcional_do_ga() -> None:
    # Antes: o cookie Adobe classificado como 'sessão' suprimia o achado funcional de `_ga`.
    ids = _run(
        (
            "_ga=GA1.2.123456; Secure; SameSite=Lax",
            "kndctr_ABC_AdobeOrg_identity=blob9f3c8d2e1a4b; Secure; SameSite=Lax",
        )
    )
    findings = {
        f.id: f
        for f in CookiesChecker().run(
            make_context(
                primary=make_probe(
                    set_cookies=(
                        "_ga=GA1.2.123456; Secure; SameSite=Lax",
                        "kndctr_ABC_AdobeOrg_identity=blob9f3c8d2e1a4b; Secure; SameSite=Lax",
                    )
                )
            )
        )
    }
    assert "COOKIE_SEM_HTTPONLY_FUNCIONAL" in ids
    assert "COOKIE_SEM_HTTPONLY" not in ids  # nenhum é auth -> nada de MÉDIA
    # o `_ga` aparece de fato no achado funcional (não foi engolido)
    assert "_ga" in findings["COOKIE_SEM_HTTPONLY_FUNCIONAL"].evidence
