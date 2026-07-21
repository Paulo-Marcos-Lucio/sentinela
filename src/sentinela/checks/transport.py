"""Higiene de transporte: redirecionamento de HTTP para HTTPS."""

from __future__ import annotations

from collections.abc import Iterable

from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref


class TransportChecker(Checker):
    id = "transport"
    name = "Redirecionamento HTTP → HTTPS"
    category = Category.TRANSPORT
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        http_probe = ctx.http_probe
        if http_probe is None or not http_probe.ok:
            return

        status = http_probe.status_code
        location = http_probe.header("Location") or ""
        redireciona_https = 300 <= status < 400 and location.lower().startswith("https://")

        # Se a porta 80 respondeu (2xx/sem redirect https), servir HTTP é um problema.
        if not redireciona_https and status and status < 400:
            yield Finding(
                id="SEM_REDIRECT_HTTPS",
                title="HTTP não redireciona para HTTPS",
                category=self.category,
                severity=Severity.MEDIUM,
                description=(
                    f"A versão HTTP do site respondeu com status {status} sem redirecionar para HTTPS."
                ),
                evidence=f"HTTP {status}" + (f" · Location: {location}" if location else ""),
                impact=(
                    "Servir conteúdo por HTTP permite interceptação e adulteração "
                    "do tráfego em redes não confiáveis, além de captura de "
                    "credenciais e cookies em claro."
                ),
                recommendation=(
                    "Configure um redirecionamento 301 de todo o tráfego HTTP para "
                    "HTTPS e combine com HSTS."
                ),
                references=(ref.OWASP_TLS_CHEATSHEET, ref.MOZILLA_SSL_CONFIG),
            )
