"""Avaliação dos métodos HTTP anunciados pelo servidor.

Usa uma requisição ``OPTIONS`` (não-intrusiva) e lê o cabeçalho ``Allow`` para
identificar métodos potencialmente perigosos habilitados.
"""

from __future__ import annotations

from collections.abc import Iterable

from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

# Métodos que raramente deveriam estar expostos em produção.
_PERIGOSOS = {"PUT", "DELETE", "PATCH", "CONNECT"}


class HttpMethodsChecker(Checker):
    id = "http-methods"
    name = "Métodos HTTP permitidos"
    category = Category.METHODS
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        probe = ctx.client.request("OPTIONS", ctx.target.url)
        if not probe.ok:
            return

        allow = probe.header("Allow")
        if not allow:
            return  # servidor não anuncia métodos via OPTIONS — inconclusivo

        metodos = {m.strip().upper() for m in allow.split(",") if m.strip()}

        if "TRACE" in metodos:
            yield Finding(
                id="HTTP_TRACE_HABILITADO",
                title="Método TRACE habilitado",
                category=self.category,
                severity=Severity.MEDIUM,
                description="O servidor anuncia suporte ao método `TRACE`.",
                evidence=f"Allow: {allow}",
                impact=(
                    "TRACE ecoa a requisição recebida e pode ser abusado em ataques "
                    "de Cross-Site Tracing (XST) para exfiltrar cabeçalhos sensíveis "
                    "como cookies, mesmo protegidos por HttpOnly."
                ),
                recommendation="Desabilite o método TRACE no servidor/proxy.",
                references=(ref.RFC_TRACE, ref.OWASP_SECURE_HEADERS),
            )

        expostos = sorted(metodos & _PERIGOSOS)
        if expostos:
            yield Finding(
                id="HTTP_METODOS_PERIGOSOS",
                title="Métodos de escrita expostos via OPTIONS",
                category=self.category,
                severity=Severity.LOW,
                description=f"O servidor anuncia métodos de escrita: {', '.join(expostos)}.",
                evidence=f"Allow: {allow}",
                impact=(
                    "Métodos como PUT/DELETE, se não estritamente controlados por "
                    "autenticação e autorização, podem permitir alteração ou remoção "
                    "de recursos no servidor."
                ),
                recommendation=(
                    "Confirme se esses métodos são realmente necessários; se não, "
                    "desabilite-os. Se forem, garanta autenticação e autorização rígidas."
                ),
                references=(ref.OWASP_TOP10,),
            )
