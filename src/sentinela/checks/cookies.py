"""Análise de flags de segurança em cookies (Secure, HttpOnly, SameSite)."""

from __future__ import annotations

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


# Nomes que sugerem cookie de sessão/autenticação — onde a falta de HttpOnly é séria
# (XSS rouba a sessão). Em cookie funcional/analytics, JS pode precisar lê-lo: não é MEDIUM.
_SESSION_HINTS = (
    "sess",
    "sid",
    "auth",
    "token",
    "jwt",
    "sso",
    "login",
    "logon",
    "remember",
    "csrf",
    "xsrf",
    "access",
    "refresh",
    "id_token",
    "phpsessid",
    "jsessionid",
    "connect.sid",
)


def _is_session_like(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _SESSION_HINTS)


def _parse_cookie(raw: str) -> _Cookie:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    flags = {p.lower() for p in parts[1:]}
    same_site = None
    path = None
    domain = None
    for p in parts[1:]:
        low = p.lower()
        if low.startswith("samesite="):
            same_site = p.split("=", 1)[1].strip()
        elif low.startswith("path="):
            path = p.split("=", 1)[1].strip()
        elif low.startswith("domain="):
            domain = p.split("=", 1)[1].strip()
    return _Cookie(
        name=name or "(sem nome)",
        secure="secure" in flags,
        http_only="httponly" in flags,
        same_site=same_site,
        path=path,
        domain=domain,
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

        serves_https = ctx.primary.final_url.startswith("https://") or ctx.target.is_https
        cookies = [_parse_cookie(c) for c in ctx.primary.set_cookies]

        sem_httponly = [c.name for c in cookies if not c.http_only]
        sem_secure = [c.name for c in cookies if not c.secure]
        sem_samesite = [c.name for c in cookies if not c.same_site]

        if sem_httponly:
            session_like = [n for n in sem_httponly if _is_session_like(n)]
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
            else:
                yield Finding(
                    id="COOKIE_SEM_HTTPONLY_FUNCIONAL",
                    title="Cookie(s) sem HttpOnly (aparentemente funcionais)",
                    category=self.category,
                    severity=Severity.LOW,
                    description=f"Cookies sem `HttpOnly`: {', '.join(sem_httponly)}.",
                    evidence=", ".join(sem_httponly),
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
            yield Finding(
                id="COOKIE_SEM_SECURE",
                title="Cookie(s) sem flag Secure em site HTTPS",
                category=self.category,
                severity=Severity.MEDIUM,
                description=f"Cookies sem `Secure`: {', '.join(sem_secure)}.",
                evidence=", ".join(sem_secure),
                impact=(
                    "Sem Secure, o cookie pode ser enviado por HTTP em claro e "
                    "capturado por um atacante na rede."
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
