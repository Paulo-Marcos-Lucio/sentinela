"""Superfície de formulários e injeção — análise PASSIVA do HTML já baixado.

Zero tráfego de ataque. Este checker lê apenas ``ctx.primary`` (a resposta que o motor
já buscou uma vez) e a URL do alvo. É a fatia de injeção que se pode avaliar com
honestidade sem enviar payload: higiene de formulário (credencial trafegando em GET,
formulário postando em HTTP, CSRF ausente em formulário que muda estado), reflexão de
parâmetro (a pré-condição do XSS refletido) e dado sensível na query string.

A CONFIRMAÇÃO ativa — provar SQLi/XSS com payload seguro — é da edição Pro. Aqui a
regra é não afirmar o que não se pode provar por fora: a superfície é sinalizada como
superfície, com confiança baixa e um convite a confirmar. Um scanner sério é honesto
sobre a fronteira entre "isto é uma superfície de ataque" e "isto é explorável".
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from html import escape
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit

from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

# Nome de campo/param que denuncia credencial ou dado sensível trafegando à mostra.
_SENSIVEL = re.compile(
    r"senha|password|passwd|pwd|secret|token|api[_-]?key|apikey|auth|"
    r"cart(a|ã)o|card|cvv|cpf|cnpj|access[_-]?token|session",
    re.IGNORECASE,
)
# Campo escondido que caracteriza defesa anti-CSRF (padrão dos frameworks).
_CSRF = re.compile(r"csrf|xsrf|_token|authenticity_token|__requestverification", re.IGNORECASE)


@dataclass(slots=True)
class _Campo:
    name: str
    type: str


@dataclass(slots=True)
class _Form:
    method: str  # "get" | "post"
    action: str
    campos: list[_Campo] = field(default_factory=list)

    @property
    def tem_senha(self) -> bool:
        return any(c.type == "password" or _SENSIVEL.search(c.name or "") for c in self.campos)

    @property
    def tem_csrf(self) -> bool:
        return any(_CSRF.search(c.name or "") for c in self.campos)


class _ColetorDeForms(HTMLParser):
    """Extrai ``<form>`` e seus campos do HTML. Tolerante a marcação quebrada — é
    um parser de leitura, não um validador; entrada hostil não pode derrubá-lo."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[_Form] = []
        self._atual: _Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._atual = _Form(
                method=(a.get("method") or "get").strip().lower(),
                action=a.get("action", ""),
            )
        elif tag in ("input", "textarea", "select") and self._atual is not None:
            self._atual.campos.append(
                _Campo(
                    name=a.get("name", ""),
                    type=(a.get("type") or "text").strip().lower(),
                )
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._atual is not None:
            self.forms.append(self._atual)
            self._atual = None

    def close(self) -> None:  # noqa: D102
        super().close()
        if self._atual is not None:  # <form> sem </form>: não perde o que já foi lido
            self.forms.append(self._atual)
            self._atual = None


class FormsChecker(Checker):
    """Superfície de injeção e formulários — passiva, sem enviar payload."""

    id = "forms"
    name = "Superfície de formulários e injeção (passiva)"
    category = Category.SURFACE
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        probe = ctx.primary
        if probe is None or not probe.ok:
            return
        html = probe.body_snippet or ""

        yield from self._forms(html)
        yield from self._reflexao(html, ctx)
        yield from self._dado_sensivel_na_url(ctx)

    # --- formulários ------------------------------------------------------- #
    def _forms(self, html: str) -> Iterable[Finding]:
        parser = _ColetorDeForms()
        try:
            parser.feed(html)
            parser.close()
        except Exception:  # noqa: BLE001 — parser de leitura nunca derruba a varredura
            return

        senha_get = False
        form_http = False
        csrf_ausente = False
        for f in parser.forms:
            if f.method == "get" and f.tem_senha:
                senha_get = True
            # Form com credencial cujo `action` aponta para http:// (conteúdo misto). O caso
            # "página inteira em HTTP com campo de senha" já é coberto por SENHA_SEM_HTTPS
            # no checker de conteúdo — reportar aqui de novo seria penalidade dupla.
            if f.tem_senha and f.action.lower().startswith("http://"):
                form_http = True
            # CSRF só é exigível de formulário que MUDA estado (POST). Form GET de busca
            # não precisa de token — exigir seria falso positivo.
            if f.method == "post" and not f.tem_csrf:
                csrf_ausente = True

        if senha_get:
            yield Finding(
                id="SENHA_EM_GET",
                title="Credencial trafega na query string (formulário GET)",
                category=self.category,
                severity=Severity.HIGH,
                description=(
                    "Um formulário com campo de senha/credencial usa `method=get`: o valor "
                    "digitado vai na URL."
                ),
                evidence="Formulário com campo sensível e method=get.",
                impact=(
                    "Credencial na URL é registrada em log de servidor, histórico do navegador, "
                    "cabeçalho `Referer` enviado a terceiros e cache de proxy. Vaza sem que ninguém "
                    "precise interceptar o tráfego."
                ),
                recommendation="Envie formulários com credencial por `method=post` sobre HTTPS.",
                references=(ref.OWASP_TLS_CHEATSHEET, ref.OWASP_INPUT_VALIDATION),
            )
        if form_http:
            yield Finding(
                id="FORMULARIO_CREDENCIAL_SEM_HTTPS",
                title="Formulário com credencial postando para destino HTTP (conteúdo misto)",
                category=self.category,
                severity=Severity.MEDIUM,
                description=(
                    "Um formulário com campo sensível tem `action` apontando para um endereço "
                    "`http://` — a página pode até ser segura, mas o envio dos dados não é."
                ),
                evidence="Formulário sensível com `action` em HTTP.",
                impact=(
                    "A credencial trafega em claro no momento do envio e pode ser lida e "
                    "adulterada por qualquer intermediário na rede — mesmo que a página seja HTTPS."
                ),
                recommendation="Aponte o `action` do formulário para um endereço HTTPS.",
                references=(ref.OWASP_TLS_CHEATSHEET,),
            )
        if csrf_ausente:
            yield Finding(
                id="CSRF_TOKEN_AUSENTE",
                title="Formulário que muda estado sem token anti-CSRF",
                category=self.category,
                severity=Severity.MEDIUM,
                description=(
                    "Um formulário `method=post` não traz nenhum campo escondido com cara de "
                    "token anti-CSRF (csrf/xsrf/_token/authenticity_token)."
                ),
                evidence="Formulário POST sem campo de token anti-CSRF.",
                impact=(
                    "Sem token sincronizador (ou proteção equivalente por cookie SameSite), um "
                    "site malicioso pode induzir o navegador da vítima a submeter esse formulário "
                    "em nome dela — Cross-Site Request Forgery."
                ),
                recommendation=(
                    "Inclua um token anti-CSRF por sessão no formulário e valide-o no servidor, "
                    "e/ou marque os cookies de sessão como `SameSite=Lax|Strict`. Confirme a "
                    "exploração real na edição Pro."
                ),
                references=(ref.OWASP_CSRF,),
            )

    # --- reflexão de parâmetro (superfície de XSS) ------------------------- #
    def _reflexao(self, html: str, ctx: ScanContext) -> Iterable[Finding]:
        params = parse_qsl(urlsplit(ctx.target.url).query, keep_blank_values=False)
        refletidos: list[str] = []
        for nome, valor in params:
            if len(valor) < 4:  # valores curtos casam por acaso — ruído
                continue
            # Reflexão CRUA (não escapada) é o sinal de superfície de XSS. Se o valor
            # aparece já escapado, o servidor tratou — não sinalizamos.
            if valor in html and escape(valor, quote=False) != valor:
                refletidos.append(nome)
            elif valor in html and escape(valor) == valor and re.search(r"[<>\"'&]", valor):
                # valor com meta-char aparece cru: reflexão sem escape
                refletidos.append(nome)
        # Deduplica preservando ordem.
        refletidos = list(dict.fromkeys(refletidos))
        if refletidos:
            yield Finding(
                id="REFLEXAO_DE_PARAMETRO",
                title="Parâmetro refletido sem escape (superfície de XSS)",
                category=self.category,
                severity=Severity.LOW,
                description=(
                    "O valor do(s) parâmetro(s) "
                    f"`{'`, `'.join(refletidos)}` é devolvido no corpo da página sem escape de "
                    "HTML. É a pré-condição de um XSS refletido."
                ),
                evidence=f"Parâmetro(s) refletido(s): {', '.join(refletidos)}",
                impact=(
                    "Se um desses valores alcançar um contexto executável do HTML sem sanitização "
                    "por contexto, um atacante consegue rodar JavaScript no navegador da vítima "
                    "(roubo de sessão, ações em nome dela)."
                ),
                recommendation=(
                    "Escape a saída por contexto (HTML, atributo, JS, URL) e aplique uma CSP "
                    "restritiva. A CONFIRMAÇÃO com marcador inerte é feita na edição Pro."
                ),
                references=(ref.OWASP_XSS, ref.OWASP_CSP_CHEATSHEET),
            )

    # --- dado sensível na URL ---------------------------------------------- #
    def _dado_sensivel_na_url(self, ctx: ScanContext) -> Iterable[Finding]:
        params = parse_qsl(urlsplit(ctx.target.url).query, keep_blank_values=True)
        sensiveis = [nome for nome, _ in params if _SENSIVEL.search(nome)]
        if sensiveis:
            yield Finding(
                id="DADO_SENSIVEL_NA_URL",
                title="Dado sensível na query string",
                category=self.category,
                severity=Severity.LOW,
                description=(
                    "A URL do alvo carrega parâmetro com nome sensível "
                    f"(`{'`, `'.join(dict.fromkeys(sensiveis))}`)."
                ),
                evidence=f"Parâmetro(s): {', '.join(dict.fromkeys(sensiveis))}",
                impact=(
                    "Valores na query string vazam por log de servidor, histórico, `Referer` e "
                    "cache — mesmo sob HTTPS. Não é lugar para segredo."
                ),
                recommendation="Transporte segredo/credencial no corpo da requisição, nunca na URL.",
                references=(ref.OWASP_INPUT_VALIDATION,),
            )
