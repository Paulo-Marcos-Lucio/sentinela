"""Leitura de arquivos públicos padronizados (robots.txt) — não-intrusiva.

Diferente da sondagem de rotas sensíveis (que é INTRUSIVA — ver ``exposure``), o
``/robots.txt`` é um arquivo que o site publica DELIBERADAMENTE para ser lido por
agentes automatizados (RFC 9309); todo buscador o consulta. Lê-lo é parte de uma
visita normal, não uma sondagem. Esta checagem apenas SUPERFICIALIZA os caminhos
de aparência sensível que o próprio site anuncia em ``Disallow`` — revelando
superfície de ataque que o dono frequentemente não percebe estar publicando.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urljoin

from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

# Termos que, num caminho de Disallow, sugerem área sensível/administrativa.
_SENSIVEIS = (
    "admin",
    "backup",
    "config",
    "secret",
    "senha",
    "password",
    "private",
    "interno",
    "internal",
    "db",
    "database",
    "sql",
    "dump",
    "old",
    "bak",
    "test",
    "staging",
    "homolog",
    "git",
    "svn",
    "apikey",
    "api-key",
    "token",
    "credential",
    "wp-admin",
    "phpmyadmin",
    "console",
    "painel",
    "manager",
    "debug",
)
# Termo sensível ancorado no início do caminho ou após um separador — evita casar
# 'log' dentro de 'blog' ou 'test' dentro de 'contest'.
_SENS_RE = re.compile(r"(?:^|[/._\-])(?:" + "|".join(_SENSIVEIS) + r")", re.IGNORECASE)
_DISALLOW_RE = re.compile(r"^\s*Disallow\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


class WellKnownChecker(Checker):
    id = "well-known"
    name = "Arquivos públicos (robots.txt)"
    category = Category.INFO_DISCLOSURE
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        if not ctx.primary.ok:
            return  # host inalcançável: não gastar outro timeout buscando robots.txt
        url = urljoin(ctx.target.origin + "/", "robots.txt")
        probe = ctx.client.get(url)
        if not probe.ok or probe.status_code != 200:
            return
        body = probe.body_snippet
        lowered_body = body.lower()
        # Se veio HTML, é uma página de erro/catch-all — não é um robots.txt real.
        if "<html" in lowered_body or "<!doctype" in lowered_body:
            return

        sensiveis: list[str] = []
        for match in _DISALLOW_RE.finditer(body):
            caminho = match.group(1)
            if caminho in ("/", "*"):
                continue
            if _SENS_RE.search(caminho):
                sensiveis.append(caminho)

        if not sensiveis:
            return
        amostra = sensiveis[:8]
        yield Finding(
            id="ROBOTS_CAMINHOS_SENSIVEIS",
            title="robots.txt revela caminhos sensíveis",
            category=self.category,
            severity=Severity.INFO,
            description=(
                "O `/robots.txt` público lista em `Disallow` caminhos de aparência "
                "sensível (áreas administrativas, backups, configs)."
            ),
            evidence=" · ".join(amostra),
            impact=(
                "O robots.txt não protege nada — apenas pede que buscadores não indexem. "
                "Listar áreas sensíveis ali entrega ao atacante um mapa direto de onde "
                "procurar, sem nenhum esforço de descoberta."
            ),
            recommendation=(
                "Não use o robots.txt como controle de acesso. Proteja as áreas sensíveis "
                "com autenticação/autorização e evite enumerá-las ali (use `noindex` por "
                "página ou bloqueio por rede)."
            ),
            references=(ref.RFC_ROBOTS, ref.OWASP_TOP10),
        )
