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
        # O alvo em si é servido em texto aberto? Esse é o pior defeito de transporte que
        # existe, e ele NÃO depende da sonda da porta 80. Sem este ramo, um site 100% em
        # HTTP com cabeçalhos impecáveis tirava 92/100 conceito A (medido).
        # O `return` é obrigatório: é o de-duplicador. Sem ele a mesma causa raiz
        # renderia SEM_HTTPS (20) + SEM_REDIRECT_HTTPS (8) e a penalidade dobraria.
        if ctx.target.scheme == "http" and ctx.primary.ok and ctx.primary.final_url.startswith("http://"):
            yield Finding(
                id="SEM_HTTPS",
                title="Alvo servido sem HTTPS (texto aberto)",
                category=self.category,
                severity=Severity.HIGH,
                description=(
                    f"A resposta final do alvo continua em `{ctx.primary.final_url}` — o site é "
                    "servido sem TLS."
                ),
                evidence=f"URL final: {ctx.primary.final_url}",
                impact=(
                    "Todo o tráfego (páginas, formulários, cookies de sessão e credenciais) "
                    "trafega em claro e pode ser lido e ADULTERADO por qualquer um no caminho "
                    "de rede — provedor, Wi-Fi público, proxy corporativo. Navegadores modernos "
                    "marcam o site como 'Não seguro'."
                ),
                recommendation=(
                    "Publique o site em HTTPS (certificado gratuito via ACME/Let's Encrypt), "
                    "redirecione todo o HTTP para HTTPS com 301 e ative HSTS."
                ),
                references=(ref.OWASP_TLS_CHEATSHEET, ref.MOZILLA_SSL_CONFIG),
            )
            return

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
