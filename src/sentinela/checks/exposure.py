"""Sondagem de arquivos e rotas sensíveis expostos (INTRUSIVO — opt-in).

Esta checagem envia requisições GET para caminhos conhecidos por vazarem dados
(``/.git/HEAD``, ``/.env`` etc.). Embora sejam somente leituras (nunca escreve
nem apaga nada), constituem tráfego que vai além de "visitar o site". Por isso
só executa quando o operador declara explicitamente autorização (`--autorizado`).

Cada caminho tem uma **assinatura de conteúdo**: um 200 genérico (comum em SPAs
com rota catch-all) não gera achado — só dispara quando o corpo realmente casa
com o padrão do artefato sensível. Isso derruba os falsos-positivos.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urljoin

from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

_GIT_HEAD_RE = re.compile(r"^(ref:\s+refs/|[0-9a-f]{40})", re.IGNORECASE)
# `export KEY=val` é sintaxe .env aceita (python-dotenv, dotenv-ruby, docker) e chaves
# MINÚSCULAS são válidas (docker compose, php dotenv). O `^[A-Z0-9_]+=` antigo perdia as
# duas formas — um .env real vazando senha passava batido (classe FN-08).
_ENV_RE = re.compile(r"^(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=", re.MULTILINE)

_GIT_CONFIG_RE = re.compile(r"\[core\]|repositoryformatversion|\[remote \"", re.IGNORECASE)

# `not_proven` dos caminhos confirmados: o GET real prova que o caminho está público e
# devolve o conteúdo esperado — não prova nada além disso. Sem esta lista, o campo
# `exploitability_proven=True` sozinho leria como "achado 100% comprovado", quando na
# verdade validade de credencial e alcance do vazamento continuam por confirmar.
_NAO_PROVADO_EXPOSICAO_CONFIRMADA: tuple[str, ...] = (
    "que o conteúdo exposto contém segredo válido e em uso — só foi confirmado que o "
    "caminho responde publicamente com o conteúdo esperado",
    "qualquer ação além da leitura do próprio caminho (nenhum segredo encontrado foi usado)",
)


def _is_git_head(body: str) -> bool:
    return bool(_GIT_HEAD_RE.match(body.strip()))


def _is_dotenv(body: str) -> bool:
    lowered = body.lower()
    if "<html" in lowered or "<!doctype" in lowered:
        return False
    return bool(_ENV_RE.search(body))


def _is_git_config(body: str) -> bool:
    """Formato do `.git/config` (INI git): seção `[core]`, `repositoryformatversion` ou
    `[remote "..."]`. Assinatura de conteúdo — um 200 genérico não dispara."""
    if "<html" in body.lower() or "<!doctype" in body.lower():
        return False
    return bool(_GIT_CONFIG_RE.search(body))


def _is_svn_entries(body: str) -> bool:
    """Formato do `.svn/entries` (v10-): 1ª linha é o número do formato e há
    uma linha isolada `dir`/`file`. Bem mais específico que a substring 'dir'."""
    lines = [line.strip() for line in body.strip().splitlines()]
    if not lines or not lines[0].isdigit():
        return False
    return any(line in ("dir", "file") for line in lines)


def _contains(needle: str) -> Callable[[str], bool]:
    return lambda body: needle.lower() in body.lower()


@dataclass(frozen=True, slots=True)
class _Path:
    path: str
    finding_id: str
    title: str
    severity: Severity
    signature: Callable[[str], bool]
    impact: str
    recommendation: str
    references: tuple[str, ...]


_PATHS: tuple[_Path, ...] = (
    _Path(
        path="/.git/HEAD",
        finding_id="GIT_EXPOSTO",
        title="Repositório .git exposto",
        severity=Severity.CRITICAL,
        signature=_is_git_head,
        impact=(
            "Um diretório .git acessível permite baixar todo o histórico do "
            "código-fonte — incluindo segredos, credenciais e lógica de negócio "
            "que deveriam ser privados."
        ),
        recommendation=(
            "Bloqueie o acesso a `/.git` no servidor web e nunca faça deploy do "
            "diretório de controle de versão para produção."
        ),
        references=(ref.OWASP_TOP10,),
    ),
    _Path(
        path="/.git/config",
        finding_id="GIT_EXPOSTO",
        title="Repositório .git exposto (config)",
        severity=Severity.CRITICAL,
        signature=_is_git_config,
        impact=(
            "O arquivo de configuração do Git revela remotes, branches e a estrutura do "
            "repositório, e sua presença indica que todo o diretório .git está acessível — "
            "de onde se reconstrói o código-fonte e seus segredos."
        ),
        recommendation=(
            "Bloqueie o acesso a `/.git` no servidor web e nunca faça deploy do diretório de "
            "controle de versão para produção."
        ),
        references=(ref.OWASP_TOP10,),
    ),
    _Path(
        path="/.env",
        finding_id="DOTENV_EXPOSTO",
        title="Arquivo .env exposto",
        severity=Severity.CRITICAL,
        signature=_is_dotenv,
        impact=(
            "Arquivos .env costumam guardar credenciais de banco, chaves de API e "
            "segredos de aplicação. Exposição equivale a vazamento direto de segredos."
        ),
        recommendation=(
            "Remova o arquivo da raiz pública, bloqueie o acesso e **rotacione "
            "imediatamente** qualquer segredo que possa ter sido exposto."
        ),
        references=(ref.OWASP_TOP10,),
    ),
    _Path(
        path="/.svn/entries",
        finding_id="SVN_EXPOSTO",
        title="Metadados Subversion (.svn) expostos",
        severity=Severity.HIGH,
        signature=_is_svn_entries,
        impact="Metadados de controle de versão podem revelar estrutura e fontes da aplicação.",
        recommendation="Bloqueie o acesso a `/.svn` e não publique diretórios de VCS.",
        references=(ref.OWASP_TOP10,),
    ),
    _Path(
        path="/server-status",
        finding_id="APACHE_STATUS_EXPOSTO",
        title="Apache mod_status exposto",
        severity=Severity.MEDIUM,
        signature=_contains("Apache Server Status"),
        impact=(
            "A página de status do Apache revela requisições em andamento, IPs de "
            "clientes, URLs acessadas e métricas internas do servidor."
        ),
        recommendation="Restrinja `/server-status` a redes internas ou desabilite o mod_status.",
        references=(ref.OWASP_TOP10,),
    ),
    _Path(
        path="/phpinfo.php",
        finding_id="PHPINFO_EXPOSTO",
        title="phpinfo() exposto",
        severity=Severity.HIGH,
        signature=_contains("phpinfo()"),
        impact=(
            "A saída de phpinfo() detalha versão do PHP, módulos, caminhos absolutos "
            "e variáveis de ambiente — um mapa completo para o atacante."
        ),
        recommendation="Remova arquivos phpinfo() de ambientes acessíveis publicamente.",
        references=(ref.OWASP_TOP10,),
    ),
)


class ExposureChecker(Checker):
    id = "exposure"
    name = "Arquivos e rotas sensíveis (intrusivo)"
    category = Category.EXPOSURE
    intrusive = True

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        base = ctx.target.origin + "/"
        for spec in _PATHS:
            url = urljoin(base, spec.path.lstrip("/"))
            probe = ctx.client.get(url)
            if not probe.ok or probe.status_code != 200:
                continue
            if spec.signature(probe.body_snippet):
                yield Finding(
                    id=spec.finding_id,
                    title=spec.title,
                    category=self.category,
                    severity=spec.severity,
                    description=f"O caminho `{spec.path}` respondeu 200 com conteúdo sensível.",
                    evidence=f"GET {url} → 200",
                    impact=spec.impact,
                    recommendation=spec.recommendation,
                    references=spec.references,
                    # A assinatura de conteúdo já confirmou o artefato de verdade (não um
                    # 200 genérico) — isto é ação real contra o alvo, não inferência.
                    exploitability_proven=True,
                    not_proven=_NAO_PROVADO_EXPOSICAO_CONFIRMADA,
                )

        yield from self._check_security_txt(ctx)

    def _check_security_txt(self, ctx: ScanContext) -> Iterable[Finding]:
        url = urljoin(ctx.target.origin + "/", ".well-known/security.txt")
        probe = ctx.client.get(url)
        # Um SPA com rota catch-all devolve 200 + HTML para QUALQUER caminho, e a substring
        # "contact" aparece em quase toda página — lia-se um security.txt onde não há
        # (falso NEGATIVO de SECURITY_TXT_AUSENTE). Exigir assinatura real: a resposta não
        # pode ser HTML e precisa ter um campo `Contact:` no início de linha (RFC 9116).
        corpo = probe.body_snippet or ""
        ctype = (probe.header("Content-Type") or "").lower()
        parece_html = "text/html" in ctype or "<html" in corpo.lower() or "<!doctype" in corpo.lower()
        tem_campo_contact = re.search(r"(?im)^\s*contact\s*:", corpo) is not None
        presente = probe.ok and probe.status_code == 200 and not parece_html and tem_campo_contact
        if not presente:
            yield Finding(
                id="SECURITY_TXT_AUSENTE",
                title="security.txt ausente",
                category=self.category,
                severity=Severity.INFO,
                description="Não há `/.well-known/security.txt` publicado.",
                impact=(
                    "Sem um canal padronizado de contato de segurança, pesquisadores "
                    "não sabem para onde reportar vulnerabilidades de forma responsável."
                ),
                recommendation=(
                    "Publique um `/.well-known/security.txt` (RFC 9116) com um contato "
                    "de segurança e a política de divulgação."
                ),
                references=(ref.RFC_SECURITY_TXT,),
            )
