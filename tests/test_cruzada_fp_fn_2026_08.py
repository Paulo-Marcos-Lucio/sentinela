"""Invariantes das correções da auditoria cruzada de FP/FN (2026-08-28/29).

Cada teste ataca a CLASSE (a causa-raiz), não o exemplo isolado — é o padrão
`DEFINITION_OF_DONE`. Onde a classe é uma família infinita de entradas (anti-SSRF,
cookies de remoção), o teste é property-based (Hypothesis).
"""

from __future__ import annotations

import ipaddress

from hypothesis import given, settings
from hypothesis import strategies as st

from conftest import FakeClient, make_context, make_target
from sentinela.checks.content import ContentChecker
from sentinela.checks.cookies import CookiesChecker
from sentinela.checks.cors import CorsChecker
from sentinela.checks.exposure import ExposureChecker
from sentinela.checks.forms import FormsChecker
from sentinela.checks.http_methods import HttpMethodsChecker
from sentinela.checks.security_headers import SecurityHeadersChecker
from sentinela.core import http as http_mod
from sentinela.core.context import ScanContext
from sentinela.core.engine import _classificar_primaria
from sentinela.core.http import Probe
from sentinela.core.models import Severity


def _probe(**kw) -> Probe:
    base: dict = {
        "url": "https://example.com/",
        "status_code": 200,
        "headers": {},
        "final_url": "https://example.com/",
    }
    base.update(kw)
    return Probe(**base)


def _ctx(primary: Probe, *, cabecalhos=True, documento=True, client=None, target=None) -> ScanContext:
    ctx = make_context(primary=primary, client=client, target=target)
    ctx.avaliar_cabecalhos = cabecalhos
    ctx.avaliar_documento = documento
    return ctx


# ---------------------------------------------------------------- classe C2/FN-01
def test_alvo_bloqueado_403_gera_contexto_e_suprime_documento() -> None:
    probe = _probe(status_code=403, headers={"Server": "AkamaiGHost"}, body_snippet="Access Denied")
    sit = _classificar_primaria(probe, make_target("https://example.com/"))
    assert sit.finding is not None and sit.finding.id == "ALVO_BLOQUEADO"
    assert sit.avaliar_cabecalhos is False and sit.avaliar_documento is False
    assert sit.bloqueado is True


def test_desafio_por_assinatura_mesmo_em_200_nao_e_o_alvo() -> None:
    probe = _probe(status_code=503, headers={"cf-mitigated": "challenge"}, body_snippet="Just a moment...")
    sit = _classificar_primaria(probe, make_target("https://example.com/"))
    assert sit.finding.id == "ALVO_BLOQUEADO"


def test_resposta_de_erro_generica() -> None:
    probe = _probe(status_code=404, body_snippet="not found")
    sit = _classificar_primaria(probe, make_target("https://example.com/"))
    assert sit.finding.id == "RESPOSTA_DE_ERRO"
    assert sit.avaliar_cabecalhos is False


def test_nao_html_mantem_transporte_mas_suprime_documento() -> None:
    probe = _probe(headers={"Content-Type": "application/json"})
    sit = _classificar_primaria(probe, make_target("https://example.com/"))
    assert sit.finding is None
    assert sit.avaliar_cabecalhos is True and sit.avaliar_documento is False


def test_redirect_para_outro_host_e_declarado() -> None:
    probe = _probe(final_url="https://outro-dominio.net/")
    sit = _classificar_primaria(probe, make_target("https://example.com/"))
    assert sit.finding is not None and sit.finding.id == "ALVO_REDIRECIONADO_OUTRO_HOST"
    assert "outro-dominio.net" in (sit.finding.evidence or "")


def test_gate_suprime_achados_de_ausencia_na_pagina_de_bloqueio() -> None:
    # Página de bloqueio SEM nenhum cabeçalho: sem o gate, sairia uma enxurrada de *_AUSENTE.
    ctx = _ctx(_probe(status_code=403, headers={}), cabecalhos=False, documento=False)
    assert list(SecurityHeadersChecker().run(ctx)) == []


# ---------------------------------------------------------------- CSP (FN-02/03/04)
def _sec(headers=None, headers_multi=(), body="") -> set[str]:
    probe = _probe(headers=headers or {}, headers_multi=tuple(headers_multi), body_snippet=body)
    return {f.id for f in SecurityHeadersChecker().run(_ctx(probe))}


def test_csp_sem_script_src_nem_default_src() -> None:
    ids = _sec({"Content-Security-Policy": "frame-ancestors 'none'; upgrade-insecure-requests"})
    assert "CSP_SEM_SCRIPT_SRC" in ids


def test_csp_dois_cabecalhos_intersecao_pega_o_mais_fraco() -> None:
    # header1 não governa script; header2 permite inline -> inline efetivamente liberado.
    multi = (
        ("Content-Security-Policy", "frame-ancestors 'none'"),
        ("Content-Security-Policy", "script-src 'unsafe-inline' 'self'; object-src 'none'"),
    )
    ids = _sec(headers_multi=multi)
    assert "CSP_DIRETIVA_INSEGURA" in ids


def test_csp_diretiva_duplicada_primeira_vence() -> None:
    csp = "script-src 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'"
    ids = _sec({"Content-Security-Policy": csp})
    assert "CSP_DIRETIVA_INSEGURA" in ids


def test_csp_nonce_neutraliza_unsafe_inline() -> None:
    csp = (
        "script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline' https:; object-src 'none'; base-uri 'none'"
    )
    ids = _sec({"Content-Security-Policy": csp})
    assert "CSP_DIRETIVA_INSEGURA" not in ids


def test_framing_xfo_invalido_nao_protege() -> None:
    assert "CLICKJACKING_SEM_PROTECAO" in _sec({"X-Frame-Options": "ALLOWALL"})
    assert "CLICKJACKING_SEM_PROTECAO" in _sec({"X-Frame-Options": "ALLOW-FROM https://x"})
    assert "CLICKJACKING_SEM_PROTECAO" in _sec(
        {"Content-Security-Policy": "default-src 'self'; frame-ancestors *"}
    )
    assert "CLICKJACKING_SEM_PROTECAO" not in _sec({"X-Frame-Options": "DENY"})
    assert "CLICKJACKING_SEM_PROTECAO" not in _sec({"Content-Security-Policy": "frame-ancestors 'self'"})


def test_hsts_max_age_com_aspas_nao_e_fraco() -> None:
    ids = _sec({"Strict-Transport-Security": 'max-age="63072000"; includeSubDomains'})
    assert "HSTS_FRACO" not in ids and "HSTS_AUSENTE" not in ids


# ---------------------------------------------------------------- cookies (C3/C4/C5/FN-07)
def _cook(*cookies: str) -> list:
    probe = _probe(set_cookies=tuple(cookies))
    return list(CookiesChecker().run(_ctx(probe)))


def test_cookie_de_remocao_nunca_e_auditado() -> None:
    assert _cook("sessionid=; Max-Age=0") == []
    assert _cook("sessionid=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT") == []


def test_sessao_por_token_nao_por_substring() -> None:
    # 'accessibility' e 'sidebar' NÃO são sessão (C4); nomes de auth conhecidos SÃO (FN-07).
    ids_pref = {
        f.id for f in _cook("accessibility=1; Secure; SameSite=Lax", "sidebar=1; Secure; SameSite=Lax")
    }
    assert "COOKIE_SEM_HTTPONLY" not in ids_pref
    ids_wp = {f.id for f in _cook("wordpress_logged_in_ab=1")}
    assert "COOKIE_SEM_HTTPONLY" in ids_wp
    ids_aspnet = {f.id for f in _cook(".AspNetCore.Identity.Application=1")}
    assert "COOKIE_SEM_HTTPONLY" in ids_aspnet


def test_samesite_com_espacos_e_valido() -> None:
    ids = {f.id for f in _cook("id=1; SameSite = None; Secure; HttpOnly")}
    assert "COOKIE_SEM_SAMESITE" not in ids and "COOKIE_SAMESITE_NONE_INSEGURO" not in ids


def test_secure_ausente_severidade_por_papel() -> None:
    (analytics,) = [f for f in _cook("_ga=x") if f.id == "COOKIE_SEM_SECURE"]
    assert analytics.severity is Severity.LOW
    (sessao,) = [f for f in _cook("sessionid=x") if f.id == "COOKIE_SEM_SECURE"]
    assert sessao.severity is Severity.MEDIUM


# ---------------------------------------------------------------- CORS (null) e métodos (FN-06)
def test_cors_null_com_credenciais() -> None:
    cors_probe = _probe(
        headers={
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        }
    )
    ctx = _ctx(_probe(), client=FakeClient(default=cors_probe))
    ids = {f.id for f in CorsChecker().run(ctx)}
    assert "CORS_NULL_COM_CREDENCIAIS" in ids


def test_metodos_nao_avaliados_quando_options_sem_allow() -> None:
    # OPTIONS e TRACE devolvem 200 sem Allow e sem eco -> declara NAO_AVALIADOS, não cala.
    ctx = _ctx(_probe(), client=FakeClient(default=_probe(status_code=200)))
    ids = {f.id for f in HttpMethodsChecker().run(ctx)}
    assert "METODOS_NAO_AVALIADOS" in ids


# ---------------------------------------------------------------- forms (C8/FN-05)
def _forms(html: str, truncado: bool = False) -> set[str]:
    probe = _probe(body_snippet=html, truncated=truncado)
    return {f.id for f in FormsChecker().run(_ctx(probe))}


def test_senha_em_get_exige_method_explicito() -> None:
    # form sem method (controlado por JS) NÃO deve gerar SENHA_EM_GET (C8)...
    assert "SENHA_EM_GET" not in _forms('<form><input name="cpf"></form>')
    # ...mas method=get EXPLÍCITO com credencial deve.
    assert "SENHA_EM_GET" in _forms('<form method="get"><input type="password" name="p"></form>')


def test_meta_csrf_token_conta_como_defesa() -> None:
    html = '<meta name="csrf-token" content="x"><form method="post"><input name="a"></form>'
    assert "CSRF_TOKEN_AUSENTE" not in _forms(html)


def test_forms_truncado_declara_parcial() -> None:
    assert "FORMS_NAO_AVALIADO" in _forms("<form method='post'>", truncado=True)


def test_action_sem_aspas_e_lida() -> None:
    ids = _forms(
        '<form method="post"><input type="password" name="p"></form>'.replace(
            '<form method="post">', '<form method="post" action=http://x/login>'
        )
    )
    assert "FORMULARIO_CREDENCIAL_SEM_HTTPS" in ids


# ---------------------------------------------------------------- content (C6/FN-05)
def _content(html: str) -> set[str]:
    return {f.id for f in ContentChecker().run(_ctx(_probe(body_snippet=html)))}


def test_link_canonical_http_nao_e_conteudo_misto() -> None:
    assert "CONTEUDO_MISTO" not in _content('<link rel="canonical" href="http://x/y">')
    assert "CONTEUDO_MISTO" in _content('<link rel="stylesheet" href="http://cdn/x.css">')


def test_tag_em_comentario_html_e_ignorada() -> None:
    assert "CONTEUDO_MISTO" not in _content('<!-- <img src="http://cdn/x.png"> -->')


def test_recurso_http_sem_aspas_e_conteudo_misto() -> None:
    assert "CONTEUDO_MISTO" in _content("<img src=http://cdn/x.png>")


# ---------------------------------------------------------------- exposure (FN-08)
def _exp(corpo_por_path: dict[str, str]):
    def handler(method, url, headers):
        for path, corpo in corpo_por_path.items():
            if url.endswith(path):
                return _probe(status_code=200, body_snippet=corpo)
        return _probe(status_code=404)

    cfg = None
    from sentinela.core.config import ScanConfig

    cfg = ScanConfig(intrusive=True)
    ctx = make_context(primary=_probe(), client=FakeClient(handler=handler), config=cfg)
    ctx.avaliar_cabecalhos = True
    ctx.avaliar_documento = True
    return {f.id for f in ExposureChecker().run(ctx)}


def test_env_com_export_e_minusculo() -> None:
    assert "DOTENV_EXPOSTO" in _exp({"/.env": "export DB_PASSWORD=segredo123\n"})
    assert "DOTENV_EXPOSTO" in _exp({"/.env": "db_password=segredo123\nredis_url=x\n"})


def test_git_config_reconhecido() -> None:
    assert "GIT_EXPOSTO" in _exp({"/.git/config": "[core]\n\trepositoryformatversion = 0\n"})


def test_security_txt_catchall_html_nao_conta_como_presente() -> None:
    # SPA catch-all devolve 200 + HTML com a palavra "contact" -> ainda deve faltar security.txt.
    ids = _exp({"/.well-known/security.txt": "<html><body>Contact us</body></html>"})
    assert "SECURITY_TXT_AUSENTE" in ids


# ---------------------------------------------------------------- property-based: anti-SSRF (C1)
_INTERNOS = st.sampled_from(
    ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1"]
)


@settings(max_examples=50, deadline=None)
@given(interno=_INTERNOS)
def test_ssrf_redirect_para_outro_host_interno_sempre_bloqueado(interno: str) -> None:
    # A isenção do C1 vale SÓ para o próprio host do alvo. Um alvo público que redireciona
    # para QUALQUER host interno diferente continua bloqueado (não ganha a isenção).
    alvo = "https://exemplo-publico-alvo.test/"
    ip = ipaddress.ip_address(interno)
    host = f"[{interno}]" if isinstance(ip, ipaddress.IPv6Address) else interno
    permitido = http_mod._redirect_do_alvo_permitido(
        alvo, f"http://{host}/interno", "exemplo-publico-alvo.test", frozenset()
    )
    assert permitido is False


def test_c1_upgrade_http_https_mesmo_host_e_permitido() -> None:
    alvo = "http://alvo-interno.local:8080/"
    permitido = http_mod._redirect_do_alvo_permitido(
        alvo, "https://alvo-interno.local:8443/", "alvo-interno.local", frozenset()
    )
    assert permitido is True
