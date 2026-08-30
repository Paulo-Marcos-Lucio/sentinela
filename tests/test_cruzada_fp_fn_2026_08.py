"""Invariantes das correções da auditoria cruzada de FP/FN (2026-08-28/29).

Cada teste ataca a CLASSE (a causa-raiz), não o exemplo isolado — é o padrão
`DEFINITION_OF_DONE`. Onde a classe é uma família infinita de entradas (anti-SSRF,
cookies de remoção), o teste é property-based (Hypothesis).
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

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
from sentinela.checks.tls import TlsChecker
from sentinela.core import http as http_mod
from sentinela.core.context import ScanContext
from sentinela.core.engine import _classificar_primaria
from sentinela.core.http import Probe
from sentinela.core.models import Category, Finding, Severity
from sentinela.core.scoring import compute_score


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
def test_cors_null_com_credenciais_estatico() -> None:
    # Servidor que ecoa `null` para QUALQUER origem (a sonda estática já o revela).
    cors_probe = _probe(
        headers={
            "Access-Control-Allow-Origin": "null",
            "Access-Control-Allow-Credentials": "true",
        }
    )
    ctx = _ctx(_probe(), client=FakeClient(default=cors_probe))
    ids = {f.id for f in CorsChecker().run(ctx)}
    assert "CORS_NULL_COM_CREDENCIAIS" in ids


def test_h3_cors_null_refletido_so_sob_origin_null() -> None:
    # O vetor REAL (iframe sandbox/data:): o servidor ecoa `null` SÓ quando a requisição
    # chega com `Origin: null` — invisível para a sonda de origem estática (classe H3).
    def handler(method, url, headers):
        origem = (headers or {}).get("Origin", "")
        if origem == "null":
            return _probe(
                headers={
                    "Access-Control-Allow-Origin": "null",
                    "Access-Control-Allow-Credentials": "true",
                }
            )
        return _probe(headers={})  # nenhuma reflexão para a origem arbitrária

    ctx = _ctx(_probe(), client=FakeClient(handler=handler))
    ids = {f.id for f in CorsChecker().run(ctx)}
    assert "CORS_NULL_COM_CREDENCIAIS" in ids


def test_h3_cors_allowlist_fixa_sem_null_nao_inventa_achado() -> None:
    # CONTRAPROVA: allowlist fixa que NÃO ecoa nem a origem arbitrária nem `null` → nada.
    def handler(method, url, headers):
        return _probe(
            headers={
                "Access-Control-Allow-Origin": "https://parceiro.confiavel.example",
                "Access-Control-Allow-Credentials": "true",
            }
        )

    ctx = _ctx(_probe(), client=FakeClient(handler=handler))
    ids = {f.id for f in CorsChecker().run(ctx)}
    assert "CORS_NULL_COM_CREDENCIAIS" not in ids


def test_metodos_nao_avaliados_quando_options_sem_allow() -> None:
    # OPTIONS e TRACE devolvem 200 sem Allow e sem eco -> declara NAO_AVALIADOS, não cala.
    ctx = _ctx(_probe(), client=FakeClient(default=_probe(status_code=200)))
    ids = {f.id for f in HttpMethodsChecker().run(ctx)}
    assert "METODOS_NAO_AVALIADOS" in ids


# ---------------------------------------------------------------- forms (C8/FN-05)
def _forms(html: str, truncado: bool = False) -> set[str]:
    probe = _probe(body_snippet=html, truncated=truncado)
    return {f.id for f in FormsChecker().run(_ctx(probe))}


def test_h4_senha_em_get_nativo_default_e_explicito() -> None:
    # method=get EXPLÍCITO com credencial → sempre aponta (intenção de GET declarada).
    assert "SENHA_EM_GET" in _forms('<form method="get"><input type="password" name="p"></form>')
    # DEFAULT do HTML (sem method) COM controle de submit nativo → GET nativo, vaza na URL
    # (era o buraco C8/H4: a guarda exigia method explícito e cegava este caso).
    assert "SENHA_EM_GET" in _forms(
        '<form action="/login"><input type="password" name="p"><button>Entrar</button></form>'
    )
    # CONTRAPROVA 1: SPA — onsubmit intercepta (fetch/XHR), a credencial NÃO vai na URL.
    assert "SENHA_EM_GET" not in _forms(
        '<form onsubmit="app.login();return false"><input type="password" name="p"><button>Ok</button></form>'
    )
    # CONTRAPROVA 2: default-GET SEM controle de submit nativo = provável SPA, não aponta.
    assert "SENHA_EM_GET" not in _forms('<form><input name="cpf"></form>')


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


def test_c1_upgrade_http_https_mesma_porta_ou_padrao_e_permitido() -> None:
    perm = http_mod._redirect_do_alvo_permitido
    # Upgrade legítimo (classe C1): 80 -> 443 (sem porta declarada) e MESMA porta explícita.
    assert perm("http://alvo-interno.local/", "https://alvo-interno.local/", "alvo-interno.local", frozenset()) is True
    assert (
        perm("http://alvo-interno.local:8080/", "https://alvo-interno.local:8080/", "alvo-interno.local", frozenset())
        is True
    )


def test_h5_upgrade_para_outra_porta_nao_e_isento() -> None:
    # Regressão H5: o upgrade http->https isentava QUALQUER porta de destino, furando a guarda.
    # Agora só MESMA porta ou o par padrão 80->443 é isento; o resto cai na guarda anti-SSRF.
    perm = http_mod._redirect_do_alvo_permitido
    # http://host/ -> https://host:2376/ (Docker TLS) / :6443 (k8s): pivô de porta, NÃO isento.
    assert perm("http://alvo-interno.local/", "https://alvo-interno.local:2376/", "alvo-interno.local", frozenset()) is False
    assert perm("http://alvo-interno.local/", "https://alvo-interno.local:6443/", "alvo-interno.local", frozenset()) is False
    # E o par não-padrão 8080 -> 8443 também não ganha isenção (só mesma porta ou 80->443).
    assert (
        perm("http://alvo-interno.local:8080/", "https://alvo-interno.local:8443/", "alvo-interno.local", frozenset())
        is False
    )


# ---------------------------------------------------------------- H1: score do não-avaliado
def _finding_scoring(fid: str, sev: Severity = Severity.INFO) -> Finding:
    return Finding(
        id=fid,
        title="t",
        category=Category.TRANSPORT,
        severity=sev,
        description="d",
        recommendation="r",
    )


def test_h1_resposta_primaria_nao_avaliada_teta_a_nota_em_f() -> None:
    # Classe: TODA resposta primária que suprime as checagens do alvo teta a nota em F.
    # RESPOSTA_DE_ERRO era INFO peso 0 e NÃO tetava — um 500/404 na raiz dava 100/A com
    # todas as checagens suprimidas (o alvo nem foi avaliado).
    for fid in ("RESPOSTA_DE_ERRO", "ALVO_BLOQUEADO", "ALVO_INACESSIVEL"):
        s = compute_score([_finding_scoring(fid)])
        assert s.grade == "F", fid
        assert s.value <= 44, fid


def test_h1_alvo_avaliado_com_so_info_segue_a() -> None:
    # CONTRAPROVA: um alvo REALMENTE avaliado, com apenas achados informativos, segue 100/A.
    s = compute_score([_finding_scoring("TLS_13_AUSENTE")])
    assert s.grade == "A" and s.value == 100


# ---------------------------------------------------------------- H2: relógio ignora Age
@settings(max_examples=60, deadline=None)
@given(idade=st.integers(min_value=0, max_value=60 * 60 * 24 * 30))
def test_h2_age_compensa_date_antigo_nao_gera_divergencia(idade: int) -> None:
    # RFC 7234: uma resposta de cache traz Date da geração + Age. Para QUALQUER Age>=0,
    # Date=now-Age representa deriva ZERO e NÃO pode gerar RELOGIO_LOCAL_DIVERGENTE.
    agora = datetime.now(timezone.utc)
    date = format_datetime(agora - timedelta(seconds=idade))
    ctx = _ctx(_probe(headers={"Date": date, "Age": str(idade)}))
    ids = {f.id for f in TlsChecker()._check_relogio(ctx)}
    assert "RELOGIO_LOCAL_DIVERGENTE" not in ids


def test_h2_hit_de_cache_sem_age_tambem_e_suprimido() -> None:
    # Date de 8h atrás, sem Age, mas declarado Hit de CDN: o Date é da geração, não do
    # relógio da origem — abstemo-nos (a mesma classe do falso RELOGIO_LOCAL_DIVERGENTE).
    antigo = format_datetime(datetime.now(timezone.utc) - timedelta(hours=8))
    ctx = _ctx(_probe(headers={"Date": antigo, "X-Cache": "Hit from cloudfront"}))
    assert list(TlsChecker()._check_relogio(ctx)) == []
    ctx_cf = _ctx(_probe(headers={"Date": antigo, "CF-Cache-Status": "HIT"}))
    assert list(TlsChecker()._check_relogio(ctx_cf)) == []


def test_h2_deriva_real_sem_cache_ainda_e_denunciada() -> None:
    # CONTRAPROVA: Date 8h no passado, SEM Age nem sinal de cache = relógio de fato divergente.
    antigo = format_datetime(datetime.now(timezone.utc) - timedelta(hours=8))
    ctx = _ctx(_probe(headers={"Date": antigo}))
    ids = {f.id for f in TlsChecker()._check_relogio(ctx)}
    assert "RELOGIO_LOCAL_DIVERGENTE" in ids


# ---------------------------------------------------------------- H6: CSP script-src-elem/-attr
def test_h6_csp_com_script_src_elem_governa_script() -> None:
    ids = _sec(
        {"Content-Security-Policy": "script-src-elem 'self'; script-src-attr 'none'; object-src 'none'"}
    )
    # `script-src-elem`/`script-src-attr` governam a execução de scripts: não é "sem script-src".
    assert "CSP_SEM_SCRIPT_SRC" not in ids
    # E as diretivas são restritivas ('self'/'none'), então NÃO se inventa "inline permitido".
    assert "CSP_DIRETIVA_INSEGURA" not in ids


def test_h6_csp_sem_nenhuma_diretiva_de_script_ainda_dispara() -> None:
    # CONTRAPROVA: CSP só com object-src/base-uri (nenhuma diretiva de script) ainda acusa.
    ids = _sec({"Content-Security-Policy": "object-src 'none'; base-uri 'self'"})
    assert "CSP_SEM_SCRIPT_SRC" in ids


# ---------------------------------------------------------------- H7: cookie com token ambíguo
def test_h7_token_ambiguo_sozinho_nao_e_sessao() -> None:
    # Palavra genérica num nome FUNCIONAL, com valor trivial, NÃO é sessão (classe H7).
    for cookie in (
        "refresh_rate=30; Secure; SameSite=Lax",
        "early_access=1; Secure; SameSite=Lax",
        "login_layout=grid; Secure; SameSite=Lax",
        "remember_dismissed=1; Secure; SameSite=Lax",
    ):
        ids = {f.id for f in _cook(cookie)}
        assert "COOKIE_SEM_HTTPONLY" not in ids, cookie


def test_h7_token_ambiguo_corroborado_e_sessao() -> None:
    # CONTRAPROVA: token FORTE no nome, OU valor com forma de sessão, mantêm MEDIUM.
    assert "COOKIE_SEM_HTTPONLY" in {f.id for f in _cook("access_token=abc; Secure; SameSite=Lax")}
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1IjoxfQ.c2lnbmF0dXJl"
    assert "COOKIE_SEM_HTTPONLY" in {f.id for f in _cook(f"remember_me={jwt}; Secure; SameSite=Lax")}
    # E as plataformas conhecidas seguem intactas (não regride FN-07).
    assert "COOKIE_SEM_HTTPONLY" in {f.id for f in _cook("wordpress_logged_in_ab=1; Secure; SameSite=Lax")}
    assert "COOKIE_SEM_HTTPONLY" in {f.id for f in _cook(".AspNetCore.Identity.Application=1; Secure; SameSite=Lax")}


# ---------------------------------------------------------------- H8: TRACE eco real
def test_h8_trace_com_eco_real_dispara() -> None:
    # OPTIONS sem Allow → sonda TRACE. Eco REAL: Content-Type message/http + linha refletida.
    corpo = "TRACE / HTTP/1.1\r\nHost: example.com\r\nX-Custom: 1\r\n"

    def handler(method, url, headers):
        if method == "TRACE":
            return _probe(status_code=200, headers={"Content-Type": "message/http"}, body_snippet=corpo)
        return _probe(status_code=200)  # OPTIONS 200 sem Allow

    ctx = _ctx(_probe(), client=FakeClient(handler=handler))
    ids = {f.id for f in HttpMethodsChecker().run(ctx)}
    assert "HTTP_TRACE_HABILITADO" in ids


def test_h8_trace_que_so_menciona_o_host_nao_e_xst() -> None:
    # CONTRAPROVA (classe FN-06): 200 cujo corpo cita o domínio mas NÃO ecoa a requisição.
    def handler(method, url, headers):
        if method == "TRACE":
            return _probe(
                status_code=200,
                headers={"Content-Type": "text/html"},
                body_snippet="<html><a href='https://example.com/'>example.com</a></html>",
            )
        return _probe(status_code=200)

    ctx = _ctx(_probe(), client=FakeClient(handler=handler))
    ids = {f.id for f in HttpMethodsChecker().run(ctx)}
    assert "HTTP_TRACE_HABILITADO" not in ids
