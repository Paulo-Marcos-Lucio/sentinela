"""Avaliação dos métodos HTTP anunciados pelo servidor.

Usa uma requisição ``OPTIONS`` (não-intrusiva) e lê o cabeçalho ``Allow`` para
identificar métodos potencialmente perigosos habilitados.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

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
        if not ctx.primary.ok:
            return  # host inalcançável: não gastar outro timeout sondando o mesmo alvo
        if not ctx.avaliar_cabecalhos:
            return  # resposta é bloqueio/erro, não o alvo (classe C2)
        probe = ctx.client.request("OPTIONS", ctx.target.url)
        if not probe.ok:
            return

        allow = probe.header("Allow")
        if not allow:
            # Silêncio não é ausência (classe FN-06): OPTIONS sem `Allow` NÃO significa que
            # TRACE/PUT estão desabilitados. Sondamos TRACE (leitura pura — ecoa a
            # requisição, não altera estado) para pegar o XST real, e declaramos que o
            # inventário por OPTIONS ficou inconclusivo em vez de calar.
            yield from self._sondar_trace(ctx)
            yield Finding(
                id="METODOS_NAO_AVALIADOS",
                title="Métodos HTTP não puderam ser inventariados (OPTIONS sem Allow)",
                category=self.category,
                severity=Severity.INFO,
                description=(
                    "A resposta ao `OPTIONS` não trouxe o cabeçalho `Allow`; os métodos "
                    "aceitos pelo servidor não puderam ser enumerados por esta via."
                ),
                evidence="OPTIONS sem cabeçalho Allow",
                impact=(
                    "A ausência de `Allow` não é prova de que métodos de escrita (PUT/DELETE) "
                    "ou TRACE estejam desabilitados — apenas de que o servidor não os anuncia. "
                    "Afirmar segurança a partir deste silêncio seria enganoso."
                ),
                recommendation=(
                    "Confirme os métodos aceitos diretamente (ex.: `curl -X TRACE`/`-X PUT`) "
                    "num ambiente autorizado; a edição Pro faz esse inventário ativo."
                ),
                references=(ref.OWASP_TOP10,),
            )
            return

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

    def _sondar_trace(self, ctx: ScanContext) -> Iterable[Finding]:
        """Sonda TRACE (idempotente, read-only) para detectar Cross-Site Tracing real quando
        o OPTIONS não anuncia métodos. Um TRACE habilitado responde 200 ecoando a requisição."""
        probe = ctx.client.request("TRACE", ctx.target.url)
        if not probe.ok or probe.status_code != 200:
            return
        corpo = (probe.body_snippet or "").upper()
        ctype = (probe.header("Content-Type") or "").lower()
        # Eco REAL de TRACE: ou o Content-Type é `message/http`, ou o corpo reflete a LINHA
        # DE REQUISIÇÃO que enviamos (`TRACE <path> HTTP/...`). O disjunto antigo "host no
        # corpo" era frouxo (classe FN-06): qualquer 200 que mencione o domínio — qualquer
        # página com um link para si mesma — virava XST falso. Um alvo que só cita o host no
        # HTML NÃO ecoa a requisição; um TRACE habilitado devolve a requisição literal.
        caminho = urlsplit(ctx.target.url).path or "/"
        linha_requisicao = f"TRACE {caminho} HTTP/".upper()
        eco = "message/http" in ctype or linha_requisicao in corpo
        if not eco:
            return
        yield Finding(
            id="HTTP_TRACE_HABILITADO",
            title="Método TRACE habilitado",
            category=self.category,
            severity=Severity.MEDIUM,
            description="O servidor respondeu ao método `TRACE` ecoando a requisição (200).",
            evidence=f"TRACE {ctx.target.url} → {probe.status_code}",
            impact=(
                "TRACE ecoa a requisição recebida e pode ser abusado em ataques de "
                "Cross-Site Tracing (XST) para exfiltrar cabeçalhos sensíveis como cookies, "
                "mesmo protegidos por HttpOnly."
            ),
            recommendation="Desabilite o método TRACE no servidor/proxy.",
            references=(ref.RFC_TRACE, ref.OWASP_SECURE_HEADERS),
        )
