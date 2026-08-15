"""Invariante de sincronia entre o catálogo real de achados e a tabela do README.

Existe porque a tabela "O que a Sentinela verifica" é preenchida à mão e o catálogo de
achados vive espalhado em treze módulos de checagem — nada impedia os dois de divergirem
silenciosamente. Achou-se, ao escrever este teste, que já tinham divergido: o checker
`exposure` (`.git/HEAD`, `.env`, `.svn/entries` — dois achados CRÍTICOS) não tinha linha
nenhuma na tabela, e três linhas existentes publicavam menos rótulo OWASP do que os achados
que o próprio checker emite (`Cabeçalhos` sem A04 por causa do HSTS, `Cookies` sem A02 por
causa de `COOKIE_PREFIXO_INVALIDO`, `Conteúdo da página` sem A02 por causa de
`CACHE_SENSIVEL_SEM_NOSTORE`). As quatro correções foram feitas junto com este teste.

A malha é deliberadamente dinâmica, no molde de `esteira/tests/test_catalogo.py`: os IDs de
achado de cada checker são extraídos do PRÓPRIO código-fonte do módulo (não de uma lista
mantida à parte), e a classificação OWASP vem da fonte única (`knowledge/mapping._TAGS`).
Um achado novo — ou uma reclassificação — entra na verificação sem precisar lembrar de
atualizar este arquivo; só a tabela do README precisa acompanhar.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from sentinela.core.registry import ALL_CHECKERS
from sentinela.knowledge.mapping import _TAGS

_RAIZ = Path(__file__).resolve().parent.parent

# Todo achado nasce como `Finding(id="ALGO_ASSIM", ...)` direto, ou como `finding_id="ALGO_ASSIM"`
# numa dataclass de especificação (`_SimpleHeader`, `_Path`) que o `run()` percorre depois. Os
# dois padrões usam MAIÚSCULO_COM_UNDERSCORE — o `id`/`name` minúsculo-com-hífen do próprio
# Checker (ex.: "security-headers") nunca casa com este regex, então não precisa ser filtrado.
_ID_LITERAL_RE = re.compile(r'(?:\bid|\bfinding_id)\s*=\s*"([A-Z][A-Z0-9_]*)"')

# Nome da linha na tabela do README -> ID do Checker correspondente (`core/registry.ALL_CHECKERS`).
# Mantido à parte porque a tabela é prosa para o cliente, não uma lista de IDs — mas o teste
# abaixo garante que nenhum checker fica de fora dele nem do README.
_MODULO_PARA_CHECKER_ID: dict[str, str] = {
    "Cabeçalhos": "security-headers",
    "TLS / Certificado": "tls",
    "Transporte": "transport",
    "Cookies": "cookies",
    "CORS": "cors",
    "Métodos HTTP": "http-methods",
    "Exposição de info": "info-disclosure",
    "Conteúdo da página": "content",
    "Formulários & injeção (passiva)": "forms",
    "Arquivos públicos": "well-known",
    "Arquivos e rotas sensíveis": "exposure",
    "Superfície de ataque": "subdomain-takeover",
    "DNS / E-mail": "dns-email",
}


def _finding_ids_do_checker(checker_id: str) -> frozenset[str]:
    """IDs de achado declarados no módulo-fonte do checker (lido do disco, não de memória)."""
    cls = next(c for c in ALL_CHECKERS if c.id == checker_id)
    caminho = inspect.getsourcefile(cls)
    assert caminho is not None
    texto = Path(caminho).read_text(encoding="utf-8")
    return frozenset(_ID_LITERAL_RE.findall(texto))


def _codigos_owasp_reais(checker_id: str) -> frozenset[str]:
    """Códigos OWASP (`A02`, não o rótulo completo) que o checker de fato pode emitir."""
    codigos = set()
    for finding_id in _finding_ids_do_checker(checker_id):
        tag = _TAGS.get(finding_id)
        assert tag is not None, (
            f"{finding_id!r} (emitido por {checker_id!r}) não tem entrada em "
            f"knowledge/mapping._TAGS — todo achado precisa de classificação, mesmo "
            f"que seja `Tag(None, None, None)` de propósito."
        )
        if tag.owasp:
            codigos.add(tag.owasp.split(":", 1)[0])
    return frozenset(codigos)


def _secao_o_que_verifica() -> str:
    """O trecho do README entre o cabeçalho da seção e o próximo `## `, isolado para o regex
    de tabela não pegar linhas de OUTRAS tabelas do arquivo (opções da CLI, Pro × Público…)."""
    texto = (_RAIZ / "README.md").read_text(encoding="utf-8")
    trecho = texto.split("## ✨ O que a Sentinela verifica", 1)[1]
    return trecho.split("\n## ", 1)[0]


_LINHA_TABELA = re.compile(r"^\|\s*\*\*(.+?)\*\*\s*\|.*\|\s*([A-Z0-9:/ ]+?)\s*\|\s*$", re.MULTILINE)


def _tabela_do_readme() -> dict[str, frozenset[str]]:
    """`{nome do módulo: códigos OWASP publicados}` lido da tabela real do README."""
    return {
        nome: frozenset(c.strip() for c in codigos.split("/"))
        for nome, codigos in _LINHA_TABELA.findall(_secao_o_que_verifica())
    }


def test_todo_checker_registrado_tem_linha_mapeada() -> None:
    """Um checker novo em `ALL_CHECKERS` sem entrada aqui é o defeito que motivou o teste:
    o `exposure` existia no código, rodava, emitia CRÍTICO — e não aparecia em lugar nenhum."""
    assert set(_MODULO_PARA_CHECKER_ID.values()) == {c.id for c in ALL_CHECKERS}


def test_readme_documenta_todos_os_modulos_mapeados() -> None:
    """A linha existe de verdade na tabela (não só na promessa do dict acima)."""
    assert set(_tabela_do_readme()) == set(_MODULO_PARA_CHECKER_ID)


def test_readme_declara_o_owasp_real_de_cada_checker() -> None:
    publicado = _tabela_do_readme()
    divergentes = {
        nome: {"publicado": sorted(publicado[nome]), "real": sorted(_codigos_owasp_reais(checker_id))}
        for nome, checker_id in _MODULO_PARA_CHECKER_ID.items()
        if publicado[nome] != _codigos_owasp_reais(checker_id)
    }
    assert divergentes == {}


def test_todo_achado_extraido_tem_pelo_menos_um_id() -> None:
    """Guarda contra o regex quebrar em silêncio (ex.: um checker refatorado para gerar IDs
    só em runtime) e a malha inteira passar a validar um conjunto vazio sem avisar ninguém."""
    vazios = [c.id for c in ALL_CHECKERS if not _finding_ids_do_checker(c.id)]
    assert vazios == []
