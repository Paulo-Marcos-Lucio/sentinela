"""Análise passiva do conteúdo HTML da página (não-intrusiva).

Trabalha exclusivamente sobre o corpo que o servidor já entregou na visita à
página (``ctx.primary.body_snippet``) — nenhuma requisição extra. Cobre riscos
que só aparecem no HTML renderizado e que os cabeçalhos não revelam:

* **Conteúdo misto**: página HTTPS que ainda carrega sub-recursos por HTTP.
* **Sub-recurso de terceiro sem SRI**: ``<script>``/``<link>`` de outra origem
  sem ``integrity`` — risco de cadeia de suprimentos (se o CDN for comprometido,
  roda JavaScript arbitrário na sua página, com total confiança do navegador).
* **Formulário com ``action`` em HTTP**: dados (inclusive credenciais) enviados
  em texto aberto.
* **Campo de senha sobre HTTP**: página de login servida sem HTTPS.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlsplit

from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.http import Probe
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

# Sub-recursos carregados por HTTP (conteúdo misto). Só elementos que BUSCAM
# recurso — ``<a href>`` é navegação, não conteúdo misto, e fica de fora.
_HTTP_RESOURCE_RE = re.compile(
    r"<(?:script|img|iframe|source|embed|audio|video|track|object)\b[^>]*?"
    r"\b(?:src|data)\s*=\s*[\"']http://([^\"'>\s]+)",
    re.IGNORECASE,
)
_HTTP_LINK_RE = re.compile(
    r"<link\b[^>]*?\bhref\s*=\s*[\"']http://([^\"'>\s]+)",
    re.IGNORECASE,
)

_SCRIPT_TAG_RE = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
_LINK_TAG_RE = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_SRC_ATTR_RE = re.compile(r"\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_HREF_ATTR_RE = re.compile(r"\bhref\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_REL_STYLESHEET_RE = re.compile(r"\brel\s*=\s*[\"'][^\"']*\bstylesheet\b", re.IGNORECASE)
_INTEGRITY_RE = re.compile(r"\bintegrity\s*=", re.IGNORECASE)

_FORM_ACTION_HTTP_RE = re.compile(r"<form\b[^>]*?\baction\s*=\s*[\"']http://([^\"'>\s]+)", re.IGNORECASE)
_PASSWORD_INPUT_RE = re.compile(r"<input\b[^>]*?\btype\s*=\s*[\"']password[\"']", re.IGNORECASE)

_MAX_EVIDENCIA = 5


def _host_of(url: str) -> str:
    """Host (minúsculo, sem porta) de uma URL absoluta ou protocol-relative (``//host``)."""
    if url.startswith("//"):
        url = "https:" + url
    return (urlsplit(url).hostname or "").lower()


def _base(host: str) -> str:
    """Domínio "registrável" aproximado (dois últimos rótulos) para comparar mesma-origem.

    Heurística deliberadamente conservadora: em TLDs compostos (``com.br``) pode
    tratar terceiros como mesma-origem — erra para MENOS achados, nunca para
    afirmar de forma exagerada.
    """
    labels = host.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


class ContentChecker(Checker):
    id = "content"
    name = "Conteúdo HTML da página (mixed content, SRI, formulários)"
    category = Category.CONTENT
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        probe = ctx.primary
        if not probe.ok or not probe.body_snippet:
            return
        body = probe.body_snippet
        serves_https = probe.final_url.startswith("https://") or ctx.target.is_https

        yield from self._check_mixed_content(body, serves_https)
        yield from self._check_sri(body, ctx.target.host)
        yield from self._check_insecure_form(body)
        yield from self._check_password_over_http(body, serves_https)
        yield from self._check_cache_sensivel(body, probe)

    def _check_mixed_content(self, body: str, serves_https: bool) -> Iterable[Finding]:
        if not serves_https:
            return  # conteúdo misto só existe numa página HTTPS
        urls = {m.group(1) for m in _HTTP_RESOURCE_RE.finditer(body)}
        urls |= {m.group(1) for m in _HTTP_LINK_RE.finditer(body)}
        if not urls:
            return
        amostra = sorted(urls)[:_MAX_EVIDENCIA]
        yield Finding(
            id="CONTEUDO_MISTO",
            title="Conteúdo misto (recursos HTTP em página HTTPS)",
            category=self.category,
            severity=Severity.MEDIUM,
            description=(
                "A página é servida por HTTPS, mas referencia sub-recursos por HTTP (conteúdo misto)."
            ),
            evidence="http://" + " · http://".join(amostra),
            impact=(
                "Recursos carregados por HTTP trafegam em texto aberto e podem ser "
                "interceptados ou adulterados por um atacante na rede, comprometendo a "
                "integridade da página mesmo com HTTPS. Navegadores bloqueiam conteúdo "
                "misto ativo e podem quebrar funcionalidades."
            ),
            recommendation=(
                "Sirva todos os sub-recursos por HTTPS. Considere "
                "`Content-Security-Policy: upgrade-insecure-requests` como reforço."
            ),
            references=(ref.MDN_MIXED_CONTENT, ref.OWASP_TOP10),
        )

    def _check_sri(self, body: str, target_host: str) -> Iterable[Finding]:
        alvo = _base(target_host.lower())
        externos: set[str] = set()

        def _consumir(url: str, tag: str) -> None:
            if url.startswith("http://"):
                return  # cleartext já é tratado como conteúdo misto
            host = _host_of(url)
            if host and _base(host) != alvo and not _INTEGRITY_RE.search(tag):
                externos.add(host)

        for tag in _SCRIPT_TAG_RE.findall(body):
            m = _SRC_ATTR_RE.search(tag)
            if m:
                _consumir(m.group(1), tag)
        for tag in _LINK_TAG_RE.findall(body):
            if not _REL_STYLESHEET_RE.search(tag):
                continue
            m = _HREF_ATTR_RE.search(tag)
            if m:
                _consumir(m.group(1), tag)

        if not externos:
            return
        amostra = sorted(externos)[:_MAX_EVIDENCIA]
        yield Finding(
            id="SRI_AUSENTE",
            title="Sub-recurso de terceiro sem Subresource Integrity (SRI)",
            category=self.category,
            severity=Severity.LOW,
            description=(
                "Há scripts/estilos carregados de origens externas sem o atributo `integrity` (SRI)."
            ),
            evidence=", ".join(amostra),
            impact=(
                "Sem SRI, se o servidor de terceiro (CDN) for comprometido ou sequestrado, "
                "o navegador executa o código adulterado com total confiança — um vetor "
                "clássico de ataque à cadeia de suprimentos."
            ),
            recommendation=(
                'Adicione `integrity="sha384-..."` e `crossorigin="anonymous"` aos '
                "`<script>`/`<link>` de terceiros, fixando o hash da versão esperada."
            ),
            references=(ref.MDN_SRI, ref.OWASP_TOP10),
        )

    def _check_insecure_form(self, body: str) -> Iterable[Finding]:
        acoes = {m.group(1) for m in _FORM_ACTION_HTTP_RE.finditer(body)}
        if not acoes:
            return
        amostra = sorted(acoes)[:_MAX_EVIDENCIA]
        yield Finding(
            id="FORM_ACTION_INSEGURA",
            title="Formulário envia dados por HTTP (action em texto aberto)",
            category=self.category,
            severity=Severity.MEDIUM,
            description="Há formulário(s) cujo `action` aponta para uma URL HTTP.",
            evidence="http://" + " · http://".join(amostra),
            impact=(
                "Tudo que o usuário digitar no formulário (inclusive login e senha) é "
                "enviado em texto aberto e pode ser capturado por quem estiver na rede."
            ),
            recommendation="Aponte o `action` do formulário para uma URL HTTPS.",
            references=(ref.MDN_MIXED_CONTENT, ref.OWASP_TOP10),
        )

    def _check_cache_sensivel(self, body: str, probe: Probe) -> Iterable[Finding]:
        # Só páginas SENSÍVEIS (com campo de senha) — evita ruído em página comum.
        if not _PASSWORD_INPUT_RE.search(body):
            return
        cc = (probe.header("Cache-Control") or "").lower()
        if any(diretiva in cc for diretiva in ("no-store", "no-cache", "private")):
            return
        yield Finding(
            id="CACHE_SENSIVEL_SEM_NOSTORE",
            title="Página com campo de senha sem Cache-Control restritivo",
            category=self.category,
            severity=Severity.LOW,
            description=(
                "A página contém um campo de senha, mas não define `Cache-Control` "
                "com `no-store`/`no-cache`/`private`."
            ),
            evidence=f"Cache-Control: {probe.header('Cache-Control') or '(ausente)'}",
            impact=(
                "Sem cache restritivo, dados sensíveis digitados no formulário podem ficar "
                "armazenados no cache do navegador ou de um proxy compartilhado, acessíveis a "
                "quem usar o mesmo dispositivo/rede depois."
            ),
            recommendation=(
                "Envie `Cache-Control: no-store` (ou `no-cache, private`) nas páginas que "
                "tratam dados sensíveis/credenciais."
            ),
            references=(ref.OWASP_SECURE_HEADERS,),
        )

    def _check_password_over_http(self, body: str, serves_https: bool) -> Iterable[Finding]:
        if serves_https or not _PASSWORD_INPUT_RE.search(body):
            return
        yield Finding(
            id="SENHA_SEM_HTTPS",
            title="Campo de senha em página servida por HTTP",
            category=self.category,
            severity=Severity.HIGH,
            description="A página é servida por HTTP e contém um campo de senha.",
            impact=(
                "A senha digitada trafega em texto aberto na rede, exposta a captura por "
                "qualquer atacante no caminho — uma falha grave de confidencialidade."
            ),
            recommendation=(
                "Sirva a página de login exclusivamente por HTTPS e force o "
                "redirecionamento de HTTP para HTTPS."
            ),
            references=(ref.MDN_MIXED_CONTENT, ref.OWASP_TOP10),
        )
