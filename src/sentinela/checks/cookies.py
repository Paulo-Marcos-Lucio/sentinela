"""Análise de flags de segurança em cookies (Secure, HttpOnly, SameSite)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref


@dataclass(frozen=True, slots=True)
class _Cookie:
    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    path: str | None
    domain: str | None
    removal: bool = False
    """Cookie de REMOÇÃO (Max-Age=0 / expires no passado / valor vazio ou 'deleted'): é a
    ordem de APAGAR o cookie (Django/Rails delete_cookie, logout). Não carrega valor vivo —
    cobrar HttpOnly/Secure dele é falso positivo (não há nada a proteger nem a roubar)."""


# Cookies de sessão/autenticação de plataformas conhecidas — reconhecidos por SUBSTRING
# porque o nome inteiro é inequívoco (não casa por acaso). wordpress_logged_in_* e
# .AspNetCore.Identity.Application são cookies de AUTENTICAÇÃO reais que a lista antiga de
# dicas (baseada em 'sess'/'auth'/'token') não pegava -> eram rebaixados a "funcional" (FN-07).
_SESSAO_CONHECIDA = (
    "wordpress_logged_in",
    "wordpress_sec",
    "wp-postpass",
    "aspnetcore.identity",
    "aspnet.applicationcookie",
    ".aspxauth",
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "connect.sid",
    "laravel_session",
    "ci_session",
    "_session_id",
    "sessionid",
    "jwt",
)

# Dicas curtas/ambíguas: só valem como TOKEN inteiro do nome, nunca como substring solta.
# 'access' NÃO pode marcar 'accessibility', nem 'sid' marcar 'sidebar' (classe C4/FN-07).
_SESSAO_TOKENS = {
    "sess",
    "session",
    "sessao",
    "sid",
    "ssid",
    "auth",
    "authentication",
    "token",
    "jwt",
    "sso",
    "login",
    "logon",
    "logged",
    "remember",
    "access",
    "refresh",
    "identity",
    "credential",
    "credentials",
}


def _tokens_do_nome(name: str) -> list[str]:
    """Quebra o nome do cookie em tokens: separa camelCase e corta em não-alfanuméricos.
    `mldataSessionId` -> ['mldata','session','id']; `accessibility` -> ['accessibility']."""
    espacado = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [t for t in re.split(r"[^a-zA-Z0-9]+", espacado.lower()) if t]


# Cookie de CSRF no padrão double-submit (Laravel/Axios `XSRF-TOKEN`, Django `csrftoken`,
# Angular `XSRF-TOKEN`, csurf `_csrf`): o JavaScript PRECISA lê-lo para copiar o valor no
# cabeçalho — marcá-lo HttpOnly QUEBRA a aplicação, e a doc do Django diz explicitamente
# que HttpOnly ali "não oferece proteção prática". O que importa nesse cookie é Secure +
# SameSite, e ambos já têm achado próprio e independente do nome.
_CSRF_HINTS = ("csrf", "xsrf")
# Desempate: um `csrf_session_id` é sessão, não token de CSRF.
_SESSAO_FORTE = ("sess", "sid", "jwt")


def _is_csrf_like(name: str) -> bool:
    lowered = name.lower()
    return any(h in lowered for h in _CSRF_HINTS) and not any(h in lowered for h in _SESSAO_FORTE)


def _is_session_like(name: str) -> bool:
    lowered = name.lower()
    if any(conhecida in lowered for conhecida in _SESSAO_CONHECIDA):
        return True
    return any(t in _SESSAO_TOKENS for t in _tokens_do_nome(name))


def _parse_cookie(raw: str) -> _Cookie:
    parts = [p.strip() for p in raw.split(";")]
    name, _, value = (parts[0] if parts else "").partition("=")
    name = name.strip()
    value = value.strip()
    # RFC 6265bis §5.6: o nome do atributo é trimado de espaço e comparado case-insensitive.
    # `SameSite = None` (com espaços em volta do `=`) é válido — o `startswith("samesite=")`
    # antigo não casava e rendia COOKIE_SEM_SAMESITE falso.
    flags: set[str] = set()
    attrs: dict[str, str] = {}
    for p in parts[1:]:
        chave, sep, valor = p.partition("=")
        chave = chave.strip().lower()
        if sep:
            attrs[chave] = valor.strip()
        else:
            flags.add(chave)
    same_site = attrs.get("samesite")
    max_age = attrs.get("max-age")
    expires = attrs.get("expires", "")
    removal = (
        (max_age is not None and max_age.strip().lstrip("+-").isdigit() and int(max_age) <= 0)
        or "1970" in expires
        or value == ""
        or value.lower() == "deleted"
    )
    return _Cookie(
        name=name or "(sem nome)",
        secure="secure" in flags,
        http_only="httponly" in flags,
        same_site=same_site,
        path=attrs.get("path"),
        domain=attrs.get("domain"),
        removal=removal,
    )


def _prefixo_violado(c: _Cookie) -> bool:
    """Verdadeiro se o nome usa prefixo de segurança sem cumprir os requisitos.

    ``__Secure-`` exige ``Secure``. ``__Host-`` exige ``Secure`` + ``Path=/`` e a
    AUSÊNCIA de ``Domain``. Requisitos não cumpridos → o navegador ignora o cookie.
    """
    if c.name.startswith("__Host-"):
        return not (c.secure and c.path == "/" and c.domain is None)
    if c.name.startswith("__Secure-"):
        return not c.secure
    return False


class CookiesChecker(Checker):
    id = "cookies"
    name = "Flags de segurança de cookies"
    category = Category.COOKIES
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        if not ctx.primary.ok or not ctx.primary.set_cookies:
            return
        if not ctx.avaliar_cabecalhos:
            # Resposta primária é bloqueio de WAF/erro: os cookies são da borda, não do
            # alvo — o motor já emitiu o contexto (classe C2).
            return

        serves_https = ctx.primary.final_url.startswith("https://") or ctx.target.is_https
        # Cookies de REMOÇÃO (Max-Age=0/expires 1970/valor vazio) não carregam valor vivo:
        # cobrar HttpOnly/Secure/SameSite deles é falso positivo (classe C5).
        cookies = [c for c in (_parse_cookie(c) for c in ctx.primary.set_cookies) if not c.removal]
        if not cookies:
            return

        sem_httponly = [c.name for c in cookies if not c.http_only]
        sem_secure = [c.name for c in cookies if not c.secure]
        sem_samesite = [c.name for c in cookies if not c.same_site]

        if sem_httponly:
            # Três baldes, nesta ordem: CSRF (esperado), sessão/auth (grave), funcional.
            csrf_like = [n for n in sem_httponly if _is_csrf_like(n)]
            session_like = [n for n in sem_httponly if n not in csrf_like and _is_session_like(n)]
            if csrf_like:
                yield Finding(
                    id="COOKIE_CSRF_LEGIVEL_POR_JS",
                    title="Cookie de CSRF legível por JavaScript (esperado no padrão double-submit)",
                    category=self.category,
                    severity=Severity.INFO,
                    description=f"Cookies com cara de token CSRF sem `HttpOnly`: {', '.join(csrf_like)}.",
                    evidence=", ".join(csrf_like),
                    impact=(
                        "Um token de CSRF NÃO é a sessão: roubá-lo não sequestra sessão nenhuma. "
                        "No padrão double-submit (Angular, Axios/Laravel, Django com AJAX) o "
                        "JavaScript precisa ler esse cookie para copiar o valor no cabeçalho — "
                        "marcá-lo `HttpOnly` quebra a aplicação. O que importa aqui é `Secure` "
                        "(sem ele o atacante na rede SOBRESCREVE o token — cookie tossing) e "
                        "`SameSite`; os dois têm achado próprio neste relatório."
                    ),
                    recommendation=(
                        "Confirme que este cookie carrega apenas o token de CSRF (e não a sessão). "
                        "Garanta `Secure` e `SameSite`; não force `HttpOnly` aqui."
                    ),
                    references=(ref.MDN_SETCOOKIE, ref.OWASP_COOKIES),
                )
            if session_like:
                yield Finding(
                    id="COOKIE_SEM_HTTPONLY",
                    title="Cookie de sessão/autenticação sem flag HttpOnly",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    description=f"Cookies de sessão/auth sem `HttpOnly`: {', '.join(session_like)}.",
                    evidence=", ".join(session_like),
                    impact=(
                        "Sem HttpOnly, o cookie é acessível via JavaScript "
                        "(`document.cookie`). Um XSS consegue roubar a sessão diretamente."
                    ),
                    recommendation="Marque cookies de sessão/autenticação com `HttpOnly`.",
                    references=(ref.MDN_SETCOOKIE, ref.OWASP_COOKIES),
                )
            funcionais = [n for n in sem_httponly if n not in csrf_like and n not in session_like]
            if funcionais and not session_like:
                yield Finding(
                    id="COOKIE_SEM_HTTPONLY_FUNCIONAL",
                    title="Cookie(s) sem HttpOnly (aparentemente funcionais)",
                    category=self.category,
                    severity=Severity.LOW,
                    description=f"Cookies sem `HttpOnly`: {', '.join(funcionais)}.",
                    evidence=", ".join(funcionais),
                    impact=(
                        "HttpOnly protege cookies de SESSÃO contra roubo via XSS. Nenhum destes "
                        "tem nome de sessão/auth — se realmente forem funcionais (analytics, "
                        "preferências, anti-abuso), o JS pode precisar lê-los e a ausência é aceitável."
                    ),
                    recommendation=(
                        "Confirme que nenhum destes carrega sessão/autenticação. Se algum carregar, "
                        "marque-o com `HttpOnly`."
                    ),
                    references=(ref.MDN_SETCOOKIE, ref.OWASP_COOKIES),
                )

        if serves_https and sem_secure:
            # Severidade pelo PAPEL (classe C3): a falta de Secure num cookie de
            # sessão/auth/CSRF é MÉDIA (a sessão pode vazar num downgrade); num cookie
            # puramente funcional (analytics/preferência), não há sessão a roubar -> BAIXA.
            sensiveis = [n for n in sem_secure if _is_session_like(n) or _is_csrf_like(n)]
            severidade = Severity.MEDIUM if sensiveis else Severity.LOW
            yield Finding(
                id="COOKIE_SEM_SECURE",
                title="Cookie(s) sem flag Secure em site HTTPS",
                category=self.category,
                severity=severidade,
                description=f"Cookies sem `Secure`: {', '.join(sem_secure)}.",
                evidence=", ".join(sem_secure),
                impact=(
                    "Sem Secure, o cookie pode ser enviado por HTTP em claro e capturado por um "
                    "atacante na rede. Em cookie de sessão isso vaza a sessão; em cookie funcional "
                    "(analytics/preferência) o impacto é menor, mas a flag continua recomendada."
                ),
                recommendation="Adicione a flag `Secure` a todos os cookies em sites HTTPS.",
                references=(ref.MDN_SETCOOKIE, ref.OWASP_COOKIES),
            )

        if sem_samesite:
            yield Finding(
                id="COOKIE_SEM_SAMESITE",
                title="Cookie(s) sem atributo SameSite",
                category=self.category,
                severity=Severity.LOW,
                description=f"Cookies sem `SameSite`: {', '.join(sem_samesite)}.",
                evidence=", ".join(sem_samesite),
                impact=(
                    "Sem SameSite, o cookie acompanha requisições cross-site, facilitando ataques de CSRF."
                ),
                recommendation=(
                    "Defina `SameSite=Lax` (padrão seguro) ou `Strict`; use `None` "
                    "apenas em conjunto com `Secure` quando o cross-site for necessário."
                ),
                references=(ref.MDN_SETCOOKIE, ref.OWASP_COOKIES),
            )

        samesite_none_insecure = [
            c.name for c in cookies if c.same_site and c.same_site.lower() == "none" and not c.secure
        ]
        if samesite_none_insecure:
            yield Finding(
                id="COOKIE_SAMESITE_NONE_INSEGURO",
                title="Cookie com SameSite=None sem flag Secure",
                category=self.category,
                severity=Severity.MEDIUM,
                description=f"Cookies com `SameSite=None` mas sem `Secure`: {', '.join(samesite_none_insecure)}.",
                evidence=", ".join(samesite_none_insecure),
                impact=(
                    "`SameSite=None` libera o envio do cookie em requisições cross-site e "
                    "EXIGE a flag `Secure`. Sem ela, o cookie pode trafegar por HTTP (capturável "
                    "na rede) e os navegadores modernos o rejeitam — quebrando a sessão."
                ),
                recommendation="Sempre combine `SameSite=None` com `Secure` (ou prefira `Lax`/`Strict`).",
                references=(ref.MDN_SETCOOKIE, ref.OWASP_COOKIES),
            )

        prefixo_invalido = [c.name for c in cookies if _prefixo_violado(c)]
        if prefixo_invalido:
            yield Finding(
                id="COOKIE_PREFIXO_INVALIDO",
                title="Cookie com prefixo __Host-/__Secure- mal configurado",
                category=self.category,
                severity=Severity.LOW,
                description=f"Cookies com prefixo de segurança sem os requisitos: {', '.join(prefixo_invalido)}.",
                evidence=", ".join(prefixo_invalido),
                impact=(
                    "Os prefixos `__Secure-`/`__Host-` prometem garantias ao navegador (Secure; "
                    "e, no `__Host-`, escopo travado em `Path=/` sem `Domain`). Se os requisitos "
                    "não são cumpridos, o navegador IGNORA o cookie — a proteção pretendida não existe."
                ),
                recommendation=(
                    "Para `__Secure-`, envie a flag `Secure`. Para `__Host-`, envie `Secure`, "
                    "`Path=/` e NÃO defina `Domain`."
                ),
                references=(ref.MDN_SETCOOKIE, ref.OWASP_COOKIES),
            )
