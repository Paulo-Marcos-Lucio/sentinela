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
            trace = self._sondar_trace(ctx)
            if trace is not None:
                yield trace
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
            # Anunciar não é confirmar. O ramo SEM `Allow` já exigia eco real (H8 da cruzada
            # 2026-08-30); este ramo continuava afirmando "habilitado" a partir do cabeçalho,
            # sem enviar um TRACE — a MESMA classe, no ramo que a cruzada não tocou. Agora os
            # dois passam pela mesma sonda: só o eco real emite HTTP_TRACE_HABILITADO.
            trace = self._sondar_trace(ctx)
            if trace is not None:
                yield trace
            else:
                yield Finding(
                    id="METODOS_ANUNCIADOS",
                    title="TRACE anunciado via OPTIONS, não confirmado por sondagem",
                    category=self.category,
                    severity=Severity.INFO,
                    description=(
                        "O `Allow` lista `TRACE`, mas a sonda ativa não obteve eco da requisição. "
                        "Anunciar um método não é o mesmo que tê-lo habilitado — proxies e "
                        "frameworks frequentemente listam TRACE no `Allow` e o recusam na prática."
                    ),
                    evidence=f"Allow: {allow} · sonda TRACE sem eco",
                    impact=(
                        "Tratar o anúncio como confirmação superestimaria a superfície: o laudo "
                        "afirmaria um XST que a sondagem não reproduziu."
                    ),
                    recommendation=(
                        "Se a política proíbe TRACE, remova-o também do `Allow` para evitar ruído; "
                        "a ausência de eco indica que o método não está, de fato, servindo."
                    ),
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

    def _sondar_trace(self, ctx: ScanContext) -> Finding | None:
        """Sonda TRACE (idempotente, read-only) e devolve o achado SÓ com eco real.

        Fonte única da confirmação de TRACE: os dois ramos do `run` (com e sem `Allow`)
        passam por aqui, para que "habilitado" nunca seja afirmado sem execução observada.
        Um TRACE habilitado responde 200 ecoando a requisição."""
        probe = ctx.client.request("TRACE", ctx.target.url)
        if not probe.ok or probe.status_code != 200:
            return None
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
            return None
        return Finding(
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
