"""Exposição de informação por cabeçalhos e corpo (não-intrusiva)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

# Cabeçalhos que costumam vazar produto e versão do stack.
_LEAK_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator")

# Um número de versão embutido no valor do cabeçalho (ex.: "nginx/1.18.0").
_VERSION_RE = re.compile(r"\d+\.\d+")


class InfoDisclosureChecker(Checker):
    id = "info-disclosure"
    name = "Exposição de informação"
    category = Category.INFO_DISCLOSURE
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        probe = ctx.primary
        if not probe.ok:
            return

        vazamentos: list[str] = []
        for header in _LEAK_HEADERS:
            value = probe.header(header)
            if value and (_VERSION_RE.search(value) or header != "Server"):
                vazamentos.append(f"{header}: {value}")

        if vazamentos:
            yield Finding(
                id="VERSAO_STACK_EXPOSTA",
                title="Versão do servidor/tecnologia exposta",
                category=self.category,
                severity=Severity.LOW,
                description="Cabeçalhos de resposta revelam produto e/ou versão da stack.",
                evidence=" · ".join(vazamentos),
                impact=(
                    "Divulgar produto e versão facilita o trabalho do atacante ao "
                    "mapear vulnerabilidades conhecidas (CVEs) daquela versão específica."
                ),
                recommendation=(
                    "Suprima ou minimize esses cabeçalhos (ex.: `server_tokens off` no "
                    "Nginx, `ServerTokens Prod` no Apache, remover `X-Powered-By`)."
                ),
                references=(ref.OWASP_SECURE_HEADERS, ref.OWASP_TOP10),
            )

        body = probe.body_snippet.lower()
        if "index of /" in body and "<title>index of" in body:
            yield Finding(
                id="LISTAGEM_DIRETORIO",
                title="Listagem de diretório habilitada",
                category=self.category,
                severity=Severity.MEDIUM,
                description="A resposta parece ser uma listagem automática de diretório.",
                impact=(
                    "Listagem de diretório expõe a estrutura de arquivos do servidor, "
                    "revelando backups, fontes e artefatos que não deveriam ser públicos."
                ),
                recommendation="Desabilite a listagem automática de diretórios (autoindex off).",
                references=(ref.OWASP_TOP10,),
            )
