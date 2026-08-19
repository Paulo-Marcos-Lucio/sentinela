"""Modelos de domínio da Sentinela.

Identificadores de código em inglês (padrão de mercado); todo texto destinado a
humanos — títulos, descrições, recomendações — é escrito em PT-BR, porque o
relatório final é lido pelo cliente da consultoria.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum


class Severity(IntEnum):
    """Severidade qualitativa de um achado, alinhada às faixas do CVSS.

    A ordenação (``IntEnum``) permite ordenar achados do mais grave ao menos
    grave sem lógica extra: ``sorted(findings, reverse=True)``.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """Rótulo em PT-BR usado no relatório."""
        return _SEVERITY_LABELS[self]

    @property
    def weight(self) -> int:
        """Peso do achado no cálculo da nota de higiene (0–100)."""
        return _SEVERITY_WEIGHTS[self]

    @property
    def color(self) -> str:
        """Cor `rich`/hex associada, usada no terminal e no HTML."""
        return _SEVERITY_COLORS[self]

    @classmethod
    def from_name(cls, name: str) -> Severity:
        """Converte um nome (case-insensitive, PT ou EN) em ``Severity``."""
        key = name.strip().upper()
        aliases = {
            "CRITICA": cls.CRITICAL,
            "CRÍTICA": cls.CRITICAL,
            "ALTA": cls.HIGH,
            "MEDIA": cls.MEDIUM,
            "MÉDIA": cls.MEDIUM,
            "BAIXA": cls.LOW,
            "INFO": cls.INFO,
            "INFORMATIVA": cls.INFO,
        }
        if key in cls.__members__:
            return cls[key]
        if key in aliases:
            return aliases[key]
        raise ValueError(f"Severidade desconhecida: {name!r}")


_SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "Crítica",
    Severity.HIGH: "Alta",
    Severity.MEDIUM: "Média",
    Severity.LOW: "Baixa",
    Severity.INFO: "Informativa",
}

# Pesos aplicados à nota de higiene. Não são um escore CVSS — são uma métrica
# indicativa e transparente (ver `core.scoring`), deliberadamente conservadora.
_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "#f85149",
    Severity.HIGH: "#ff7b72",
    Severity.MEDIUM: "#d29922",
    Severity.LOW: "#58a6ff",
    Severity.INFO: "#8b949e",
}


class FindingType(str, Enum):
    """O que o achado AFIRMA sobre o alvo — ortogonal à severidade.

    ``Severity`` mede "quão grave seria se fosse verdade"; ``FindingType`` mede "o que,
    de fato, foi verificado". Uma severidade CRITICAL sozinha não diz se a checagem
    confirmou exploração ou só notou uma condição que favorece um ataque — e o consumidor
    do JSON (dashboard, triagem automatizada) precisa da distinção para não tratar uma
    observação de hardening como incidente confirmado.

    - ``OBSERVATION``: uma condição notada, sem julgamento de risco embutido.
    - ``HARDENING``: falta um controle defensivo (cabeçalho, cookie flag) — não é
      exploração comprovada nem tentada, é a ausência de uma camada de proteção.
    - ``ATTACK_SURFACE``: algo alcançável de fora (rota exposta, porta aberta) que
      amplia o que um atacante pode tentar, sem que a checagem tenha tentado explorar.
    - ``SUSPECTED_VULNERABILITY``: indício de falha real, não confirmado pela checagem
      (a checagem é não-intrusiva por padrão e frequentemente não tenta provar).
    - ``CONFIRMED_VULNERABILITY``: a checagem provou a falha (ex.: resposta observada
      de uma exploração bem-sucedida), não apenas um sinal indireto.
    - ``INCONCLUSIVE``: a checagem rodou mas não conseguiu decidir (resposta ambígua).
    - ``ANALYSIS_ERROR``: a checagem não rodou até o fim (rede, timeout, exceção) — não
      é um veredito sobre o alvo, é a ausência de um.
    - ``INFO``: contexto que não é achado de risco (ex.: versão de software detectada).
    """

    OBSERVATION = "observation"
    HARDENING = "hardening"
    ATTACK_SURFACE = "attack_surface"
    SUSPECTED_VULNERABILITY = "suspected_vulnerability"
    CONFIRMED_VULNERABILITY = "confirmed_vulnerability"
    INCONCLUSIVE = "inconclusive"
    ANALYSIS_ERROR = "analysis_error"
    INFO = "info"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class Confidence(str, Enum):
    """Quão confiável é o achado em si — não é a severidade, é a certeza da checagem.

    Uma checagem que compara uma string num corpo de resposta tem confiança menor que
    uma que decodifica um certificado X.509 e lê a data de expiração dele.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class Category(str, Enum):
    """Domínio técnico de cada checagem, usado para agrupar o relatório."""

    HEADERS = "Cabeçalhos de Segurança"
    TLS = "TLS / Certificado"
    COOKIES = "Cookies"
    CORS = "CORS"
    METHODS = "Métodos HTTP"
    DNS_EMAIL = "DNS / E-mail"
    CONTENT = "Conteúdo da Página"
    INFO_DISCLOSURE = "Exposição de Informação"
    EXPOSURE = "Arquivos e Rotas Sensíveis"
    SURFACE = "Superfície de Ataque"
    TRANSPORT = "Transporte / Redirecionamento"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(frozen=True, slots=True)
class Finding:
    """Um achado individual da varredura.

    Todos os campos textuais estão em PT-BR. ``id`` é um slug estável (ex.:
    ``"HSTS_AUSENTE"``) que permite rastrear o mesmo achado entre execuções.
    """

    id: str
    title: str
    category: Category
    severity: Severity
    description: str
    recommendation: str
    impact: str = ""
    evidence: str | None = None
    references: tuple[str, ...] = ()
    subject: str | None = None
    """Ativo específico a que este achado se refere (ex.: o subdomínio), quando a mesma
    checagem pode emitir VÁRIAS instâncias do mesmo ``id`` numa varredura.

    É o que dá identidade de INSTÂNCIA no SARIF: sem ele, três subdomain takeovers
    distintos declaravam o mesmo ``partialFingerprints`` e o GitHub os fundia num alerta
    só — o cliente corrigia um e achava que tinha acabado.
    """
    type: FindingType = FindingType.OBSERVATION
    """O que o achado afirma provar (ver :class:`FindingType`).

    Default SEGURO, não neutro: uma checagem que ainda não foi revisada para declarar o
    tipo explícito cai em ``OBSERVATION`` — a classificação que menos afirma —, nunca em
    ``CONFIRMED_VULNERABILITY``. Errar por subclassificar gera, no pior caso, um achado
    real etiquetado como observação; errar por superclassificar por omissão inflaria a
    contagem de "vulnerabilidade confirmada" do relatório sem nenhuma checagem ter
    provado nada, o que é o erro que um laudo de segurança não pode cometer em silêncio.
    """
    confidence: Confidence = Confidence.LOW
    """Confiança da checagem no próprio achado (ver :class:`Confidence`).

    Default SEGURO: ``LOW`` até a checagem declarar o contrário. O consumidor do JSON
    que filtra por confiança alta não deve receber, por omissão de metadado, achados que
    ninguém calibrou — a ausência de declaração tem de se comportar como incerteza, não
    como certeza.
    """

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Finding.id não pode ser vazio")
        if not self.title:
            raise ValueError("Finding.title não pode ser vazio")


@dataclass(frozen=True, slots=True)
class Target:
    """Alvo normalizado da varredura."""

    raw: str
    scheme: str
    host: str
    port: int
    url: str

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def host_for_url(self) -> str:
        """Host pronto para compor uma URL (IPv6 literal entre colchetes)."""
        return f"[{self.host}]" if ":" in self.host else self.host

    @property
    def origin(self) -> str:
        """Origem no formato ``scheme://host[:porta]`` (porta omitida se padrão)."""
        default = {"http": 80, "https": 443}.get(self.scheme)
        host = self.host_for_url
        if self.port == default:
            return f"{self.scheme}://{host}"
        return f"{self.scheme}://{host}:{self.port}"


@dataclass(frozen=True, slots=True)
class ScanError:
    """Falha não-fatal ocorrida durante uma checagem (rede, timeout, etc.)."""

    check_id: str
    message: str


@dataclass(slots=True)
class ScanResult:
    """Resultado consolidado de uma varredura completa."""

    target: Target
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    intrusive: bool = False
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    tool_version: str = ""
    ambiente: dict[str, str] = field(default_factory=dict)
    """Condições em que ESTA varredura rodou (Python, OpenSSL, resolvedor, modo).

    Existe porque, diante de dois relatórios divergentes do mesmo alvo, não havia como
    saber qual dos dois era confiável. Vários achados dependem da máquina — a versão
    do OpenSSL decide se dá para testar TLS legado, o resolvedor decide se as checagens
    de DNS rodam, o relógio decide a validade do certificado. Carimbar isso no
    entregável é o que torna um laudo auditável meses depois.
    """

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def sorted_findings(self) -> list[Finding]:
        """Achados ordenados por severidade (desc.), depois categoria e título."""
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), f.category.value, f.title),
        )

    def counts_by_severity(self) -> dict[Severity, int]:
        counts = dict.fromkeys(Severity, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()
