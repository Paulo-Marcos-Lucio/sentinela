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
    metodo_explicito: bool = False
    tem_onsubmit: bool = False
    tem_controle_submit: bool = False
    campos: list[_Campo] = field(default_factory=list)

    @property
    def tem_senha(self) -> bool:
        return any(c.type == "password" or _SENSIVEL.search(c.name or "") for c in self.campos)

    @property
    def tem_csrf(self) -> bool:
        return any(_CSRF.search(c.name or "") for c in self.campos)

    @property
    def submete_por_url(self) -> bool:
        """O form submete de fato pela URL (GET nativo → credencial na query string)?

        GET vale tanto o explícito (`method=get`) quanto o DEFAULT do HTML (sem `method`):
        cegar o default era o buraco C8/H4 — `<form action=/login><input type=password>`
        com um `<button>` submete via GET e vaza a senha na URL. O que NÃO submete pela URL
        é o form controlado por JS: um `onsubmit=` intercepta e usa fetch/XHR. E, quando o
        método é só o default (não declarado), exigimos ainda um controle de submit nativo
        (`<button>`/`<input type=submit>`) como prova de submissão nativa — sem ele, o form
        é provável SPA e cobrar credencial-em-GET dele seria falso positivo."""
        if self.method != "get" or self.tem_onsubmit:
            return False
        return self.metodo_explicito or self.tem_controle_submit


# Extração de formulários por regex LIMITADA — O(n) e à prova de corpo hostil. O
# `HTMLParser` da stdlib é super-linear num `<script`/`<style` sem fechamento (a MESMA
# classe de DoS que o F100 matou em content.py); aqui o escaneamento de cada tag tem
# teto de bytes, então nenhum `<...>` gigante sem `>` degrada a varredura.
_ATTR_SCAN = 2048  # teto de bytes lidos por tag (igual ao content.py)
_FORM_OPEN_RE = re.compile(rf"<form\b([^>]{{0,{_ATTR_SCAN}}})>", re.IGNORECASE)
_CAMPO_RE = re.compile(rf"<(?:input|textarea|select)\b([^>]{{0,{_ATTR_SCAN}}})>", re.IGNORECASE)
_A_METHOD = re.compile(r"""\bmethod\s*=\s*["']?\s*([a-zA-Z]+)""", re.IGNORECASE)
# action com ou SEM aspas (HTML5 §13.1.2.3): sem isso, `action=http://...` escapava (FN-05).
_A_ACTION = re.compile(r"""\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""", re.IGNORECASE)
_A_NAME = re.compile(r"""\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""", re.IGNORECASE)
_A_TYPE = re.compile(r"""\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""", re.IGNORECASE)
# `onsubmit=` no <form> = interceptação por JS (submete via fetch/XHR, não pela URL).
_A_ONSUBMIT = re.compile(r"\bonsubmit\s*=", re.IGNORECASE)
# Controle de submit NATIVO no interior: <button> (default type=submit) que não seja
# type=button/reset, ou <input type=submit|image>. É a prova de que o form submete de
# forma nativa (e não é um SPA controlado por JS).
_BOTAO_SUBMIT_RE = re.compile(
    rf"""<button\b(?![^>]{{0,{_ATTR_SCAN}}}?\btype\s*=\s*["']?(?:button|reset)\b)""",
    re.IGNORECASE,
)


def _attr(regex: re.Pattern[str], texto: str) -> str:
    """Primeiro valor de atributo casado (aspas duplas, simples ou sem aspas), ou vazio."""
    m = regex.search(texto)
    if not m:
        return ""
    return next((g for g in m.groups() if g is not None), "")


def _coletar_forms(html: str) -> list[_Form]:
    """Formulários e campos, com escaneamento limitado por tag (não trava em entrada hostil).

    O `</form>` pode ser OMITIDO em HTML5 (fecha implicitamente em `</body>` ou no próximo
    `<form>`): por isso o interior vai do fim da abertura até o `</form>`, o próximo `<form>`
    ou o fim do documento — o que vier antes. Antes, um form sem fechamento era simplesmente
    ignorado e o CSRF ausente passava batido (caso form-sem-fechamento)."""
    forms: list[_Form] = []
    aberturas = list(_FORM_OPEN_RE.finditer(html))
    baixo = html.lower()
    for i, m in enumerate(aberturas):
        cabecalho = m.group(1)
        inicio = m.end()
        fim = len(html)
        fech = baixo.find("</form>", inicio)
        if fech != -1:
            fim = fech
        if i + 1 < len(aberturas):
            fim = min(fim, aberturas[i + 1].start())
        interior = html[inicio:fim]
        metodo_raw = _attr(_A_METHOD, cabecalho)
        metodo = (metodo_raw or "get").strip().lower()
        action = _attr(_A_ACTION, cabecalho)
        campos = [
            _Campo(name=_attr(_A_NAME, t), type=(_attr(_A_TYPE, t) or "text").strip().lower())
            for t in _CAMPO_RE.findall(interior)
        ]
        tem_input_submit = any(c.type in ("submit", "image") for c in campos)
        tem_controle_submit = tem_input_submit or bool(_BOTAO_SUBMIT_RE.search(interior))
        forms.append(
            _Form(
                method=metodo,
                action=action,
                metodo_explicito=bool(metodo_raw),
                tem_onsubmit=bool(_A_ONSUBMIT.search(cabecalho)),
                tem_controle_submit=tem_controle_submit,
                campos=campos,
            )
        )
    return forms


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
        if not ctx.avaliar_cabecalhos:
            return  # resposta é bloqueio/erro, não o alvo (classe C2)
        html = probe.body_snippet or ""

        yield from self._forms(html, probe.truncated)
        yield from self._reflexao(html, ctx)
        yield from self._dado_sensivel_na_url(ctx)

    # --- formulários ------------------------------------------------------- #
    def _forms(self, html: str, truncado: bool = False) -> Iterable[Finding]:
        senha_get = False
        form_http = False
        csrf_ausente = False
        # Padrão SPA/Rails: o token de CSRF vem num `<meta name="csrf-token">` e o JavaScript
        # o injeta no cabeçalho (X-CSRF-Token) de cada requisição — não há campo escondido no
        # form. Sem reconhecer isso, todo formulário POST de app assim rendia CSRF_TOKEN_AUSENTE
        # (falso positivo). csrf-param é o par do Rails.
        tem_csrf_meta = bool(
            re.search(r'<meta\b[^>]*\bname\s*=\s*[\'"]?csrf-(?:token|param)', html, re.IGNORECASE)
        )
        for f in _coletar_forms(html):
            # SENHA_EM_GET quando a credencial vai DE FATO pela URL (GET nativo). GET conta
            # tanto o explícito quanto o DEFAULT do HTML; o que isenta é a submissão por JS
            # (`onsubmit=` → fetch/XHR não põe nada na URL). Cegar o default era o buraco H4:
            # `<form action=/login><input type=password><button>` vaza a senha na query. Ver
            # `_Form.submete_por_url` para a regra completa (classe C8/H4).
            if f.submete_por_url and f.tem_senha:
                senha_get = True
            # Form com credencial cujo `action` aponta para http:// (conteúdo misto). O caso
            # "página inteira em HTTP com campo de senha" já é coberto por SENHA_SEM_HTTPS
            # no checker de conteúdo — reportar aqui de novo seria penalidade dupla.
            if f.tem_senha and f.action.lower().startswith("http://"):
                form_http = True
            # CSRF só é exigível de formulário que MUDA estado (POST). Form GET de busca
            # não precisa de token — exigir seria falso positivo.
            if f.method == "post" and not f.tem_csrf and not tem_csrf_meta:
                csrf_ausente = True

        if truncado:
            yield Finding(
                id="FORMS_NAO_AVALIADO",
                title="Formulários não puderam ser avaliados por inteiro (corpo parcial)",
                category=self.category,
                severity=Severity.INFO,
                description=(
                    "O HTML foi lido apenas parcialmente (limite de leitura/prazo/conexão): um "
                    "formulário mais adiante no documento pode não ter sido visto."
                ),
                evidence="corpo truncado",
                impact=(
                    "Este achado NÃO afirma que não há formulário inseguro: afirma que não deu "
                    "para verificar. Afirmar ausência a partir de leitura parcial faria o mesmo "
                    "alvo mudar de veredito conforme a rede."
                ),
                recommendation=(
                    "Reexecute com `--timeout` maior ou numa conexão melhor para um veredito "
                    "conclusivo sobre a superfície de formulários."
                ),
                references=(ref.OWASP_CSRF,),
            )
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
