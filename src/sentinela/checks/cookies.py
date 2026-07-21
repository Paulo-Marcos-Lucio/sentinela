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


def _parse_cookie(raw: str) -> _Cookie:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    flags = {p.lower() for p in parts[1:]}
    same_site = None
    for p in parts[1:]:
        if p.lower().startswith("samesite="):
            same_site = p.split("=", 1)[1].strip()
    return _Cookie(
        name=name or "(sem nome)",
        secure="secure" in flags,
        http_only="httponly" in flags,
        same_site=same_site,
    )


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
            yield Finding(
                id="COOKIE_SEM_HTTPONLY",
                title="Cookie(s) sem flag HttpOnly",
                category=self.category,
                severity=Severity.MEDIUM,
                description=f"Cookies sem `HttpOnly`: {', '.join(sem_httponly)}.",
                evidence=", ".join(sem_httponly),
                impact=(
                    "Sem HttpOnly, o cookie é acessível via JavaScript "
                    "(`document.cookie`). Um XSS consegue roubar a sessão diretamente."
                ),
                recommendation="Marque cookies de sessão/autenticação com `HttpOnly`.",
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
