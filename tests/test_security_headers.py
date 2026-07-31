"""Testes do analisador de cabeçalhos de segurança."""

from __future__ import annotations

from conftest import make_context, make_probe, make_target
from sentinela.checks.security_headers import SecurityHeadersChecker

# Um conjunto de cabeçalhos considerado "bom o suficiente" para não gerar achados fortes.
BONS_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": (
        "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    ),
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


def test_csp_wildcard_permissivo() -> None:
    headers = dict(BONS_HEADERS)
    headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https:; object-src 'none'; base-uri 'self'"
    )
    ids = {f.id for f in _run(headers)}
    assert "CSP_WILDCARD_PERMISSIVO" in ids


def test_csp_sem_object_src_e_base_uri() -> None:
    headers = dict(BONS_HEADERS)
    headers["Content-Security-Policy"] = "default-src 'self'"
    ids = {f.id for f in _run(headers)}
    assert "CSP_SEM_OBJECT_SRC" in ids
    assert "CSP_SEM_BASE_URI" in ids


def test_csp_default_none_nao_exige_object_src() -> None:
    headers = dict(BONS_HEADERS)
    headers["Content-Security-Policy"] = "default-src 'none'; base-uri 'self'"
    ids = {f.id for f in _run(headers)}
    assert "CSP_SEM_OBJECT_SRC" not in ids


def test_csp_apenas_report_only() -> None:
    headers = dict(BONS_HEADERS)
    del headers["Content-Security-Policy"]
    headers["Content-Security-Policy-Report-Only"] = "default-src 'self'"
    ids = {f.id for f in _run(headers)}
    assert "CSP_APENAS_REPORT_ONLY" in ids
    assert "CSP_AUSENTE" not in ids


def test_probe_com_erro_nao_gera_achados() -> None:
    probe = make_probe(error="ConnectError")
    assert list(SecurityHeadersChecker().run(make_context(primary=probe))) == []


def test_evidencia_longa_e_truncada() -> None:
    # A evidência vai para o terminal e para o Markdown: uma CSP de 4 KB numa linha só
    # destrói a leitura do relatório. O corte é o único motivo de `truncate` existir.
    from sentinela.checks._util import truncate

    assert truncate("a" * 300) == "a" * 179 + "…"
    assert truncate("a" * 300, 160) == "a" * 159 + "…"
    assert truncate("curto") == "curto"
    assert truncate("com\nquebra   e   espaços") == "com quebra e espaços"

    csp = "default-src 'self' " + " ".join(f"https://cdn{i}.exemplo.com" for i in range(40))
    headers = dict(BONS_HEADERS, **{"Content-Security-Policy": csp + "; script-src 'unsafe-inline'"})
    achado = next(f for f in _run(headers) if f.id == "CSP_DIRETIVA_INSEGURA")
    assert achado.evidence is not None
    assert len(achado.evidence) <= 180 and achado.evidence.endswith("…")


# --------------------------------------------------------------------------- #
# HSTS: os dois ramos de configuração fraca. Sem estes testes, apagar os ramos
# `max_age < HSTS_PISO` e `includeSubDomains` deixava a suíte verde.
# --------------------------------------------------------------------------- #
def test_hsts_max_age_curto_e_fraco() -> None:
    headers = dict(BONS_HEADERS, **{"Strict-Transport-Security": "max-age=300"})
    ids = {f.id for f in _run(headers)}
    assert "HSTS_FRACO" in ids


def test_hsts_longo_sem_includesubdomains() -> None:
    headers = dict(BONS_HEADERS, **{"Strict-Transport-Security": "max-age=63072000"})
    ids = {f.id for f in _run(headers)}
    assert "HSTS_SEM_SUBDOMINIOS" in ids
    assert "HSTS_FRACO" not in ids


def test_hsts_bem_configurado_nao_gera_achado() -> None:
    headers = dict(BONS_HEADERS, **{"Strict-Transport-Security": "max-age=63072000; includeSubDomains"})
    ids = {f.id for f in _run(headers)}
    assert not {i for i in ids if i.startswith("HSTS")}


# --------------------------------------------------------------------------- #
# CSP3 'strict-dynamic' / nonce / hash. A política que o Google recomenda em
# csp.withgoogle.com/docs/strict-csp era penalizada em 11 pontos: o navegador
# IGNORA `https:` e `'unsafe-inline'` quando há 'strict-dynamic' (ou nonce/hash),
# e a ferramenta recomendava REMOVER o fallback de compatibilidade — ou seja,
# recomendava enfraquecer uma configuração correta.
# --------------------------------------------------------------------------- #
_GOOGLE_STRICT_CSP = (
    "script-src 'nonce-r4nd0m' 'strict-dynamic' https: 'unsafe-inline'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)


def test_csp_strict_dynamic_do_google_nao_gera_achado() -> None:
    headers = dict(BONS_HEADERS, **{"Content-Security-Policy": _GOOGLE_STRICT_CSP})
    achados = _run(headers)
    assert [f.id for f in achados] == [], f"penalidade indevida: {[f.id for f in achados]}"


def test_csp_hash_sem_strict_dynamic_tambem_neutraliza_inline() -> None:
    headers = dict(
        BONS_HEADERS,
        **{
            "Content-Security-Policy": (
                "script-src 'sha256-abc123' 'unsafe-inline'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'"
            )
        },
    )
    assert "CSP_DIRETIVA_INSEGURA" not in {f.id for f in _run(headers)}


def test_csp_strict_dynamic_nao_perdoa_unsafe_eval() -> None:
    # 'strict-dynamic' neutraliza a allowlist e o inline, mas NÃO neutraliza eval.
    headers = dict(
        BONS_HEADERS,
        **{
            "Content-Security-Policy": (
                "script-src 'nonce-x' 'strict-dynamic' 'unsafe-eval'; object-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'"
            )
        },
    )
    achados = {f.id: f for f in _run(headers)}
    assert "CSP_DIRETIVA_INSEGURA" in achados
    assert "'unsafe-eval'" in achados["CSP_DIRETIVA_INSEGURA"].description


def test_csp_strict_dynamic_nao_esconde_unsafe_inline_em_style_src() -> None:
    # A supressão ingênua ("tem strict-dynamic → não acusa inline") criaria este falso NEGATIVO.
    headers = dict(
        BONS_HEADERS,
        **{
            "Content-Security-Policy": (
                "script-src 'nonce-x' 'strict-dynamic' https:; style-src 'unsafe-inline'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
            )
        },
    )
    achados = {f.id: f for f in _run(headers)}
    # A intenção do teste é que o inline de ESTILO não seja engolido pelo `strict-dynamic`
    # do script. O achado continua existindo — agora com o ID e o texto certos, apontando
    # para style-src em vez de acusar um script-src que está impecável.
    assert "CSP_ESTILO_INLINE" in achados
    assert "'unsafe-inline'" in achados["CSP_ESTILO_INLINE"].description


def test_csp_script_src_sobrepoe_default_src_com_strict_dynamic() -> None:
    # `default-src 'strict-dynamic'` NÃO protege um `script-src` permissivo: o script-src vence.
    headers = dict(
        BONS_HEADERS,
        **{
            "Content-Security-Policy": (
                "default-src 'strict-dynamic'; script-src 'self' https: 'unsafe-inline'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
            )
        },
    )
    ids = {f.id for f in _run(headers)}
    assert {"CSP_DIRETIVA_INSEGURA", "CSP_WILDCARD_PERMISSIVO"} <= ids


# --------------------------------------------------------------------------- #
# Políticas entregues por <meta> no HTML. Hospedagem estática (GitHub Pages, S3,
# Cloud Storage) NÃO consegue emitir cabeçalho: ler só o cabeçalho rendia
# CSP_AUSENTE + REFERRER_POLICY_AUSENTE falsos em TODO site desse tipo — medido no
# site do próprio autor. O outro lado é igualmente obrigatório: via <meta> o
# navegador ignora frame-ancestors, então o clickjacking CONTINUA desprotegido.
# --------------------------------------------------------------------------- #
_HTML_META = (
    "<!doctype html><html><head><meta charset='utf-8'>"
    '<meta http-equiv="Content-Security-Policy" '
    "content=\"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\">"
    '<meta name="referrer" content="strict-origin-when-cross-origin">'
    "</head><body>oi</body></html>"
)


def _sem_cabecalhos_de_politica() -> dict[str, str]:
    return {
        k: v for k, v in BONS_HEADERS.items() if k not in ("Content-Security-Policy", "Referrer-Policy")
    }


def _run_com_corpo(headers: dict[str, str], body: str):
    probe = make_probe(headers=headers, body=body)
    return list(SecurityHeadersChecker().run(make_context(primary=probe)))


def test_csp_e_referrer_via_meta_nao_sao_reportados_como_ausentes() -> None:
    ids = {f.id for f in _run_com_corpo(_sem_cabecalhos_de_politica(), _HTML_META)}
    assert "CSP_AUSENTE" not in ids
    assert "REFERRER_POLICY_AUSENTE" not in ids
    assert "POLITICA_VIA_META" in ids  # e o relatório DIZ que veio de <meta>


def test_sem_meta_e_sem_cabecalho_continua_ausente() -> None:
    ids = {f.id for f in _run_com_corpo(_sem_cabecalhos_de_politica(), "<html><body>oi</body></html>")}
    assert {"CSP_AUSENTE", "REFERRER_POLICY_AUSENTE"} <= ids
    assert "POLITICA_VIA_META" not in ids


def test_frame_ancestors_em_meta_nao_protege_contra_clickjacking() -> None:
    # A CSP do _HTML_META traz `frame-ancestors 'none'`, mas via <meta> o navegador a
    # IGNORA. Aceitá-la aqui seria trocar um falso positivo por um falso NEGATIVO.
    ids = {f.id for f in _run_com_corpo(_sem_cabecalhos_de_politica(), _HTML_META)}
    assert "CLICKJACKING_SEM_PROTECAO" in ids


def test_csp_de_meta_e_analisada_como_a_de_cabecalho() -> None:
    corpo = (
        "<html><head><meta http-equiv='Content-Security-Policy' "
        "content=\"script-src 'self' https: 'unsafe-inline'\"></head><body></body></html>"
    )
    ids = {f.id for f in _run_com_corpo(_sem_cabecalhos_de_politica(), corpo)}
    assert {"CSP_DIRETIVA_INSEGURA", "CSP_WILDCARD_PERMISSIVO"} <= ids


def test_meta_nao_vale_para_cabecalho_que_o_navegador_ignora_em_meta() -> None:
    # X-Content-Type-Options, Permissions-Policy e COOP por <meta> NÃO são aplicados pelo
    # navegador. Aceitá-los aqui trocaria um falso positivo por um falso NEGATIVO.
    headers = {
        k: v
        for k, v in BONS_HEADERS.items()
        if k not in ("X-Content-Type-Options", "Permissions-Policy", "Cross-Origin-Opener-Policy")
    }
    corpo = (
        "<html><head>"
        "<meta http-equiv='X-Content-Type-Options' content='nosniff'>"
        "<meta http-equiv='Permissions-Policy' content='camera=()'>"
        "<meta http-equiv='Cross-Origin-Opener-Policy' content='same-origin'>"
        "</head></html>"
    )
    ids = {f.id for f in _run_com_corpo(headers, corpo)}
    assert {"XCTO_AUSENTE", "PERMISSIONS_POLICY_AUSENTE", "COOP_AUSENTE"} <= ids


def test_cabecalho_tem_precedencia_sobre_a_meta() -> None:
    headers = dict(BONS_HEADERS, **{"Content-Security-Policy": "default-src 'none'; base-uri 'none'"})
    ids = {f.id for f in _run_com_corpo(headers, _HTML_META)}
    assert "POLITICA_VIA_META" not in ids  # a CSP veio de cabeçalho; nada a ressalvar


# --------------------------------------------------------------------------- #
# O achado tem que dizer em QUAL diretiva está o problema.
#
# Falso positivo de campo (31/07/2026, bussoladosdados.com.br): política com
# `script-src 'self' https://static.cloudflareinsights.com` — limpo — e
# `unsafe-inline` só em `style-src` recebia um achado cujo título, impacto e
# recomendação falavam de `script-src`. O cliente abre a CSP, procura no
# script-src, não acha nada, e perde a confiança no laudo inteiro.
# --------------------------------------------------------------------------- #
CSP_DE_CAMPO = (
    "default-src 'self'; script-src 'self' https://static.cloudflareinsights.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; "
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
)


def test_unsafe_inline_so_em_style_nao_acusa_script() -> None:
    headers = dict(BONS_HEADERS, **{"Content-Security-Policy": CSP_DE_CAMPO})
    achados = {f.id: f for f in _run(headers)}

    assert "CSP_DIRETIVA_INSEGURA" not in achados, "acusou script-src com script-src limpo"
    estilo = achados["CSP_ESTILO_INLINE"]
    # A regra que este teste protege: nenhum texto do achado pode apontar para script-src.
    texto = " ".join([estilo.title, estilo.description, estilo.impact, estilo.recommendation])
    assert "script-src" in estilo.description or "scripts" in estilo.description
    assert "Remova `unsafe-inline`/`unsafe-eval` da fonte de scripts" not in texto
    assert "ESTILOS" in estilo.description


def test_unsafe_inline_em_script_e_style_reporta_o_script_uma_vez_so() -> None:
    """Quando os dois estão sujos, o achado de script cobre; não duplicar o aviso."""
    headers = dict(
        BONS_HEADERS,
        **{"Content-Security-Policy": "script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'"},
    )
    ids = [f.id for f in _run(headers)]
    assert "CSP_DIRETIVA_INSEGURA" in ids
    assert "CSP_ESTILO_INLINE" not in ids


def test_unsafe_eval_em_style_src_e_inerte_e_nao_vira_achado_de_script() -> None:
    """`unsafe-eval` fora da fonte de script não faz nada — acusá-lo é ruído."""
    headers = dict(
        BONS_HEADERS,
        **{"Content-Security-Policy": "script-src 'self'; style-src 'self' 'unsafe-eval'"},
    )
    assert "CSP_DIRETIVA_INSEGURA" not in {f.id for f in _run(headers)}


def test_default_src_sem_script_src_ainda_e_tratado_como_script() -> None:
    headers = dict(BONS_HEADERS, **{"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
    assert "CSP_DIRETIVA_INSEGURA" in {f.id for f in _run(headers)}
