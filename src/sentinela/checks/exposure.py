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

from sentinela.checks._util import truncate
from sentinela.checks.base import Checker
from sentinela.core import disclosure
from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

_GIT_HEAD_RE = re.compile(r"^(ref:\s+refs/|[0-9a-f]{40})", re.IGNORECASE)
# `export KEY=val` é sintaxe .env aceita (python-dotenv, dotenv-ruby, docker) e chaves
# MINÚSCULAS são válidas (docker compose, php dotenv). O `^[A-Z0-9_]+=` antigo perdia as
# duas formas — um .env real vazando senha passava batido (classe FN-08).
_ENV_RE = re.compile(r"^(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=", re.MULTILINE)

_GIT_CONFIG_RE = re.compile(r"\[core\]|repositoryformatversion|\[remote \"", re.IGNORECASE)


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


# ---------------------------------------------------------------------------
# Assinaturas de EXFILTRAÇÃO DE DADOS.
#
# A família acima responde "este artefato existe?" (um .git, um phpinfo). Esta
# responde outra pergunta: "esta resposta está DERRAMANDO dados que não deviam ser
# públicos?". A diferença importa porque um caminho revelado pelo próprio alvo
# (robots.txt, sitemap) devolve 200 o tempo todo — o que decide se há achado não é
# o status, é o CORPO. Sem assinatura, um `/admin/` que responde a tela de login
# viraria achado, e o laudo perderia a credibilidade que sustenta o resto.
# ---------------------------------------------------------------------------

_SQL_DUMP_RE = re.compile(
    r"(?im)^\s*(?:CREATE\s+TABLE|INSERT\s+INTO|DROP\s+TABLE\s+IF\s+EXISTS)\b"
    r"|--\s+(?:MySQL|MariaDB)\s+dump\b"
    r"|--\s+PostgreSQL\s+database\s+dump\b"
)
_HTPASSWD_RE = re.compile(r"(?m)^[A-Za-z0-9._-]+:(?:\$(?:apr1|1|2[aby]|5|6)\$|\{SHA\}|[A-Za-z0-9./]{13}$)")
_AWS_CRED_RE = re.compile(r"(?im)^\s*aws_access_key_id\s*=|^\s*aws_secret_access_key\s*=")
_SPRING_ENV_RE = re.compile(r'"(?:activeProfiles|propertySources)"\s*:')
_SOURCE_MAP_RE = re.compile(r'"version"\s*:\s*3.*?"(?:sources|mappings)"\s*:', re.DOTALL)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")
# Índice de diretório listando arquivo de DADOS (não uma galeria de imagens).
_INDEX_DADOS_RE = re.compile(
    r"(?i)<(?:a|title)[^>]*>[^<]*\.(?:sql|db|sqlite3?|bak|dump|csv|xlsx?|json|env|pem|key|zip|tar\.gz|7z)\b"
)


def _is_sql_dump(body: str) -> bool:
    return not _parece_html(body) and bool(_SQL_DUMP_RE.search(body))


def _is_htpasswd(body: str) -> bool:
    return not _parece_html(body) and bool(_HTPASSWD_RE.search(body))


def _is_aws_credentials(body: str) -> bool:
    return not _parece_html(body) and bool(_AWS_CRED_RE.search(body))


def _is_spring_env(body: str) -> bool:
    return bool(_SPRING_ENV_RE.search(body))


def _is_heapdump(body: str) -> bool:
    """Cabeçalho HPROF. Um heapdump é a MEMÓRIA do processo — senha em claro,
    token de sessão, corpo de requisição de outro usuário. É exfiltração literal."""
    return body.lstrip().startswith("JAVA PROFILE 1.0")


def _is_source_map(body: str) -> bool:
    return not _parece_html(body) and bool(_SOURCE_MAP_RE.search(body))


def _is_private_key(body: str) -> bool:
    return bool(_PRIVATE_KEY_RE.search(body))


def _is_ds_store(body: str) -> bool:
    """`.DS_Store` começa com o magic `Bud1` após 4 bytes de alinhamento."""
    return "Bud1" in body[:64]


def _is_indice_de_dados(body: str) -> bool:
    baixo = body.lower()
    if "index of /" not in baixo and "<title>directory listing" not in baixo:
        return False
    return bool(_INDEX_DADOS_RE.search(body))


def _parece_html(body: str) -> bool:
    baixo = body.lower()
    return "<html" in baixo or "<!doctype html" in baixo


#: Assinaturas aplicadas a QUALQUER caminho sondado — inclusive os que o próprio alvo
#: revelou. Ordem importa: a primeira que casar decide, então o mais grave vem antes.
_EXFILTRACAO: tuple[tuple[Callable[[str], bool], str, Severity, str], ...] = (
    (
        _is_heapdump,
        "heapdump da JVM (memória do processo)",
        Severity.CRITICAL,
        "Um heapdump contém a memória viva da aplicação: senhas em claro, tokens de sessão de "
        "usuários logados e corpos de requisição de terceiros. É vazamento de dados pessoais "
        "consumado, com dever de comunicação à ANPD sob a LGPD.",
    ),
    (
        _is_private_key,
        "chave privada",
        Severity.CRITICAL,
        "Uma chave privada exposta permite personificar o servidor, decifrar tráfego capturado "
        "ou assinar artefatos em nome do titular.",
    ),
    (
        _is_sql_dump,
        "dump de banco de dados",
        Severity.CRITICAL,
        "Um dump SQL entrega a base inteira — cadastro de clientes, hashes de senha e histórico "
        "transacional. Sob a LGPD é incidente de segurança com dado pessoal.",
    ),
    (
        _is_aws_credentials,
        "credenciais de nuvem (AWS)",
        Severity.CRITICAL,
        "Credenciais de nuvem expostas dão ao atacante o mesmo poder que a aplicação tem sobre a "
        "infraestrutura: ler buckets, criar recursos, escalar privilégio.",
    ),
    (
        _is_htpasswd,
        "arquivo de senhas (.htpasswd)",
        Severity.CRITICAL,
        "Hashes de senha expostos são quebráveis offline, sem limite de tentativa e sem deixar "
        "rastro no alvo.",
    ),
    (
        _is_dotenv,
        "arquivo de ambiente (.env)",
        Severity.CRITICAL,
        "Arquivos .env guardam credenciais de banco, chaves de API e segredos de aplicação.",
    ),
    (
        _is_spring_env,
        "ambiente do Spring Actuator",
        Severity.HIGH,
        "O `/actuator/env` lista variáveis de ambiente e propriedades — inclusive senha de banco "
        "e chave de API, que o Spring só mascara quando explicitamente configurado.",
    ),
    (
        _is_indice_de_dados,
        "listagem de diretório com arquivos de dados",
        Severity.HIGH,
        "O servidor está enumerando arquivos de dados (dumps, planilhas, backups) para qualquer "
        "visitante — o atacante não precisa adivinhar nome de arquivo.",
    ),
    (
        _is_ds_store,
        "índice de diretório do macOS (.DS_Store)",
        Severity.LOW,
        "O `.DS_Store` lista os nomes dos arquivos do diretório — inclusive os que não estão "
        "linkados em lugar nenhum, revelando backups e rascunhos que se supunham invisíveis.",
    ),
    (
        _is_source_map,
        "source map do JavaScript",
        Severity.LOW,
        "O source map reconstrói o código-fonte original do front-end, revelando rotas internas, "
        "nomes de campo e lógica de negócio que se pretendia ofuscada.",
    ),
)


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


#: Caminhos que costumam DERRAMAR DADOS (não só revelar que um artefato existe).
#: Não têm assinatura própria: passam pela cascata ``_EXFILTRACAO``, que decide pelo
#: CORPO o que foi encontrado. Assim, acrescentar um caminho novo aqui não exige
#: escrever detector novo — e um caminho que responda 200 genérico nunca vira achado.
_ROTAS_DE_DADOS: tuple[str, ...] = (
    "/actuator/env",
    "/actuator/heapdump",
    "/.htpasswd",
    "/.aws/credentials",
    "/.DS_Store",
    "/.env.production",
    "/.env.bak",
    "/backup.sql",
    "/dump.sql",
    "/database.sql",
    "/config.json",
    "/appsettings.json",
    "/id_rsa",
)

#: Teto de requisições da checagem inteira. Existe para que um sitemap gigante não
#: transforme uma varredura autorizada em carga contra o alvo. O corte é SEMPRE
#: reportado — truncar em silêncio faria o laudo afirmar cobertura que não teve.
_TETO_REQUISICOES = 70


class ExposureChecker(Checker):
    id = "exposure"
    name = "Arquivos e rotas sensíveis (intrusivo)"
    category = Category.EXPOSURE
    intrusive = True

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        base = ctx.target.origin + "/"
        gastas = 0

        for spec in _PATHS:
            url = urljoin(base, spec.path.lstrip("/"))
            probe = ctx.client.get(url)
            gastas += 1
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
                )

        vistos_exfil: set[str] = set()
        for caminho in _ROTAS_DE_DADOS:
            if gastas >= _TETO_REQUISICOES:
                break
            gastas += 1
            achado = self._sondar_exfiltracao(ctx, caminho, revelado_por=None)
            if achado is not None and achado.id not in vistos_exfil:
                vistos_exfil.add(achado.id)
                yield achado

        # --- os caminhos que o PRÓPRIO alvo revelou -------------------------------
        # O robots.txt e o sitemap são o mapa que o site entrega a quem chegar. Ler o
        # mapa é passivo e o `well-known` já faz; ANDAR nele é intrusivo e é aqui.
        # Sondar o que o alvo anunciou é mais honesto que adivinhar: a evidência de que
        # o caminho existe veio do próprio alvo, não de uma lista de palpites.
        revelacao = disclosure.coletar(ctx)
        gastas += 2  # robots.txt + sitemap.xml
        cortou_por_teto = False
        for caminho in revelacao.sondaveis:
            if gastas >= _TETO_REQUISICOES:
                cortou_por_teto = True
                break
            gastas += 1
            achado = self._sondar_exfiltracao(ctx, caminho, revelado_por="robots.txt/sitemap")
            if achado is not None and achado.id not in vistos_exfil:
                vistos_exfil.add(achado.id)
                yield achado

        # Truncar em silêncio faria o laudo afirmar cobertura que não teve.
        if cortou_por_teto or revelacao.truncado_em:
            yield self._teto_atingido(revelacao, gastas)

        yield from self._check_security_txt(ctx)

    def _sondar_exfiltracao(
        self, ctx: ScanContext, caminho: str, *, revelado_por: str | None
    ) -> Finding | None:
        """Sonda um caminho e só devolve achado se o CORPO provar exfiltração.

        Um 200 não é achado. Uma tela de login em `/admin/` não é achado. O que é
        achado é a resposta carregar dado que não deveria ser público — e nesse caso
        o laudo diz QUAL assinatura casou, para que o cliente possa conferir sozinho.
        """
        url = urljoin(ctx.target.origin + "/", caminho.lstrip("/"))
        probe = ctx.client.get(url)
        if not probe.ok or probe.status_code != 200:
            return None
        corpo = probe.body_snippet or ""
        if not corpo.strip():
            return None
        for assinatura, rotulo, severidade, impacto in _EXFILTRACAO:
            if not assinatura(corpo):
                continue
            origem = f" — caminho revelado pelo próprio alvo em {revelado_por}" if revelado_por else ""
            return Finding(
                id="EXFILTRACAO_DE_DADOS",
                title=f"Exfiltração de dados em rota acessível: {rotulo}",
                category=self.category,
                severity=severidade,
                description=(
                    f"`GET {caminho}` respondeu 200 e o corpo casa com a assinatura de "
                    f"**{rotulo}**{origem}. A rota entrega dado sensível sem autenticação."
                ),
                evidence=f"GET {url} → 200 · assinatura: {rotulo} · {truncate(corpo, 120)}",
                impact=impacto,
                recommendation=(
                    "Remova o artefato da raiz pública e bloqueie a rota no servidor/CDN. "
                    "Se houver dado pessoal envolvido, trate como incidente: apure o alcance "
                    "pelos logs de acesso, **rotacione todo segredo exposto** e avalie o dever "
                    "de comunicação ao titular e à ANPD (LGPD, art. 48)."
                ),
                references=(ref.OWASP_TOP10,),
            )
        return None

    def _teto_atingido(self, revelacao: disclosure.Disclosure, gastas: int) -> Finding:
        descartados = revelacao.truncado_em or 0
        return Finding(
            id="SONDAGEM_TRUNCADA",
            title="A sondagem de rotas foi truncada pelo teto de requisições",
            category=self.category,
            severity=Severity.INFO,
            description=(
                f"O alvo revelou mais caminhos do que o teto de {_TETO_REQUISICOES} "
                "requisições permite sondar numa única varredura."
            ),
            evidence=(
                f"{gastas} requisições gastas · {len(revelacao.sondaveis)} caminhos sondáveis "
                f"revelados · {descartados} descartados pelo teto de leitura"
            ),
            impact=(
                "Os caminhos não sondados ficaram SEM VEREDICTO — não foram considerados "
                "seguros. Ausência de achado aqui não é prova de ausência de exposição."
            ),
            recommendation=(
                "Rode a varredura por seções do site (ou eleve o teto num ambiente de "
                "homologação) para cobrir os caminhos restantes."
            ),
            references=(ref.OWASP_TOP10,),
        )

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
