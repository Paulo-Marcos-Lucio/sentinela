"""Caminhos que o PRÓPRIO alvo revela sobre si — robots.txt (RFC 9309) e sitemap.xml.

Existe para haver UMA definição de "o que o site anunciou". Antes desta separação o
``well-known`` lia o ``robots.txt`` só para AVISAR que ele lista área sensível, e o
``exposure`` sondava uma lista fixa de seis palpites — e os dois lados nunca se
falavam. O alvo entregava o mapa e a ferramenta arquivava o mapa sem andar nele.

Aqui o mapa é lido e normalizado; **quem anda nele é o ``exposure``, e só com
``--autorizado``**. Ler é passivo (todo buscador lê); sondar é intrusivo.

Invariantes desta camada, todas defendidas por teste:

* **Mesma origem.** ``sitemap.xml`` pode listar URL absoluta de outro host. Sondar
  host de terceiro a partir do mapa do alvo estouraria o escopo da autorização, que
  é o erro mais caro que esta ferramenta pode cometer. Fora da origem → descartado.
* **Curinga não é caminho.** ``Disallow: /admin/*.bak$`` vira ``/admin/`` — o prefixo
  literal antes do primeiro curinga. Requisitar o ``*`` literal só gera 404 e ruído.
* **Sem duplicata**, preservando a ordem em que o alvo revelou.
* **Teto declarado.** O corte é reportado, nunca silencioso: quem lê o laudo precisa
  saber que a lista foi truncada — "inconclusivo não é ausência".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from sentinela.core.context import ScanContext

# Termos que, num caminho revelado, sugerem área sensível/administrativa.
# Fonte única: o ``well-known`` importa daqui em vez de manter cópia própria.
TERMOS_SENSIVEIS: tuple[str, ...] = (
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

#: Termos que só valem para a SONDAGEM autorizada, nunca para o aviso passivo.
#:
#: `/cliente/`, `/usuario/` e `/relatorio/` são rotas públicas legítimas em metade dos
#: sites brasileiros. Incluí-las no achado passivo do ``well-known`` encheria de ruído
#: um lugar hoje limpo — e falso positivo em varredura passiva custa mais caro do que
#: o achado vale. Na sondagem autorizada elas são seguras porque lá o que decide não é
#: o NOME do caminho, é a assinatura do CORPO: `/cliente/` com uma tela de login não
#: gera nada; `/cliente/export.csv` com um dump gera. Por isso os dois níveis existem.
TERMOS_DE_DADOS: tuple[str, ...] = (
    "export",
    "relatorio",
    "report",
    "financeiro",
    "cliente",
    "usuario",
    "upload",
    "arquivo",
    "download",
    "planilha",
    "csv",
    "xls",
)


def _ancorado(termos: tuple[str, ...]) -> re.Pattern[str]:
    """Termo ancorado no início do caminho ou após um separador — evita casar
    'log' dentro de 'blog' ou 'test' dentro de 'contest'."""
    return re.compile(r"(?:^|[/._\-])(?:" + "|".join(termos) + r")", re.IGNORECASE)


#: Conservador: o que o aviso PASSIVO do ``well-known`` considera sensível.
SENSIVEL_RE = _ancorado(TERMOS_SENSIVEIS)

#: Amplo: o que a sondagem AUTORIZADA aceita visitar. Só vira achado com assinatura.
SONDAVEL_RE = _ancorado(TERMOS_SENSIVEIS + TERMOS_DE_DADOS)

_DISALLOW_RE = re.compile(r"^\s*Disallow\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_SITEMAP_DIRETIVA_RE = re.compile(r"^\s*Sitemap\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)

#: Teto de caminhos revelados que a sondagem aceita. Existe para que um sitemap de
#: 50 mil URLs não vire 50 mil requisições contra o alvo.
TETO_REVELADOS = 40


@dataclass(frozen=True, slots=True)
class Disclosure:
    """O que o alvo anunciou sobre a própria superfície."""

    robots_lido: bool = False
    """O ``/robots.txt`` respondeu 200 com conteúdo que é de fato um robots.txt."""

    sitemap_lido: bool = False
    """Ao menos um sitemap respondeu 200 com XML utilizável."""

    caminhos: tuple[str, ...] = ()
    """Caminhos revelados, mesma origem, sem duplicata, na ordem em que apareceram."""

    sensiveis: tuple[str, ...] = ()
    """Subconjunto de :attr:`caminhos` que o aviso PASSIVO considera sensível (conservador)."""

    sondaveis: tuple[str, ...] = ()
    """Subconjunto de :attr:`caminhos` que a sondagem AUTORIZADA visita (amplo).
    Superconjunto de :attr:`sensiveis` — visitar é barato porque só a assinatura do
    corpo gera achado."""

    truncado_em: int | None = None
    """Quando o teto cortou a lista, quantos caminhos foram descartados. ``None`` = nada cortado."""

    origens_externas: tuple[str, ...] = field(default=())
    """Hosts de terceiros citados no sitemap e DESCARTADOS por estarem fora do escopo."""

    @property
    def vazio(self) -> bool:
        return not self.caminhos


def _e_html(corpo: str) -> bool:
    baixo = corpo.lower()
    return "<html" in baixo or "<!doctype html" in baixo


def _normalizar(bruto: str) -> str | None:
    """Caminho utilizável a partir de uma entrada de ``Disallow``/``<loc>``.

    Corta no primeiro curinga (``*``/``$``): o que vem antes é literal e requisitável;
    o resto é padrão, não endereço. Devolve ``None`` para o que não vale sondar.
    """
    caminho = bruto.strip()
    if not caminho:
        return None
    for curinga in ("*", "$", "?", "#"):
        pos = caminho.find(curinga)
        if pos != -1:
            caminho = caminho[:pos]
    if not caminho.startswith("/"):
        return None
    # `/` sozinho é o site inteiro — já é a resposta primária, não acrescenta nada.
    if caminho in ("/", ""):
        return None
    return caminho


def _caminho_mesma_origem(url_ou_caminho: str, origem: str) -> tuple[str | None, str | None]:
    """Devolve ``(caminho, host_externo)``.

    Uma URL absoluta só vira caminho se apontar para a MESMA origem do alvo; do
    contrário devolve o host externo para que ele seja reportado como descartado —
    o escopo da autorização é o alvo, não o que o sitemap dele cita.
    """
    if "://" not in url_ou_caminho:
        return _normalizar(url_ou_caminho), None
    partes = urlsplit(url_ou_caminho)
    alvo = urlsplit(origem)
    if (partes.scheme, partes.netloc.lower()) != (alvo.scheme, alvo.netloc.lower()):
        return None, partes.netloc.lower() or None
    caminho = partes.path or "/"
    return _normalizar(caminho), None


def coletar(ctx: ScanContext, *, teto: int = TETO_REVELADOS) -> Disclosure:
    """Lê ``robots.txt`` e os sitemaps que ele apontar, e devolve os caminhos revelados.

    Passivo: são os mesmos dois arquivos que qualquer buscador busca. Não sonda nada.
    """
    if not ctx.primary.ok:
        # Host inalcançável: não gastar timeout atrás de um mapa que não vai vir.
        return Disclosure()

    base = ctx.target.origin + "/"
    caminhos: list[str] = []
    externos: list[str] = []
    vistos: set[str] = set()

    def _juntar(caminho: str | None, externo: str | None) -> None:
        if externo and externo not in externos:
            externos.append(externo)
        if caminho and caminho not in vistos:
            vistos.add(caminho)
            caminhos.append(caminho)

    robots_lido = False
    sitemaps: list[str] = []
    probe = ctx.client.get(urljoin(base, "robots.txt"))
    if probe.ok and probe.status_code == 200 and not _e_html(probe.body_snippet):
        robots_lido = True
        corpo = probe.body_snippet
        for m in _DISALLOW_RE.finditer(corpo):
            _juntar(*_caminho_mesma_origem(m.group(1), ctx.target.origin))
        for m in _SITEMAP_DIRETIVA_RE.finditer(corpo):
            sitemaps.append(m.group(1).strip())

    # O sitemap padrão vale a tentativa mesmo sem diretiva no robots.
    if not sitemaps:
        sitemaps = [urljoin(base, "sitemap.xml")]

    sitemap_lido = False
    for url_sitemap in sitemaps[:3]:  # teto de mapas: um índice pode apontar para dezenas
        caminho_sm, externo_sm = _caminho_mesma_origem(url_sitemap, ctx.target.origin)
        if externo_sm:
            _juntar(None, externo_sm)
            continue
        if caminho_sm is None and "://" in url_sitemap:
            continue
        sm = ctx.client.get(urljoin(base, (caminho_sm or "/sitemap.xml").lstrip("/")))
        if not (sm.ok and sm.status_code == 200) or _e_html(sm.body_snippet):
            continue
        sitemap_lido = True
        for m in _LOC_RE.finditer(sm.body_snippet):
            _juntar(*_caminho_mesma_origem(m.group(1), ctx.target.origin))

    truncado = None
    if len(caminhos) > teto:
        truncado = len(caminhos) - teto
        caminhos = caminhos[:teto]

    return Disclosure(
        robots_lido=robots_lido,
        sitemap_lido=sitemap_lido,
        caminhos=tuple(caminhos),
        sensiveis=tuple(c for c in caminhos if SENSIVEL_RE.search(c)),
        sondaveis=tuple(c for c in caminhos if SONDAVEL_RE.search(c)),
        truncado_em=truncado,
        origens_externas=tuple(externos),
    )
