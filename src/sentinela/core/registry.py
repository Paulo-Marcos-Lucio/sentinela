"""Registro central das checagens disponíveis."""

from __future__ import annotations

from sentinela.checks.base import Checker
from sentinela.checks.content import ContentChecker
from sentinela.checks.cookies import CookiesChecker
from sentinela.checks.cors import CorsChecker
from sentinela.checks.dns_email import DnsEmailChecker
from sentinela.checks.exposure import ExposureChecker
from sentinela.checks.http_methods import HttpMethodsChecker
from sentinela.checks.info_disclosure import InfoDisclosureChecker
from sentinela.checks.security_headers import SecurityHeadersChecker
from sentinela.checks.subdomain_takeover import SubdomainTakeoverChecker
from sentinela.checks.tls import TlsChecker
from sentinela.checks.transport import TransportChecker
from sentinela.checks.well_known import WellKnownChecker
from sentinela.core.config import ScanConfig

# Ordem de declaração = ordem de execução (e de exibição no log).
ALL_CHECKERS: tuple[type[Checker], ...] = (
    SecurityHeadersChecker,
    TransportChecker,
    TlsChecker,
    CookiesChecker,
    CorsChecker,
    HttpMethodsChecker,
    InfoDisclosureChecker,
    ContentChecker,
    WellKnownChecker,
    DnsEmailChecker,
    SubdomainTakeoverChecker,
    ExposureChecker,
)


def build_checkers(config: ScanConfig) -> list[Checker]:
    """Instancia as checagens habilitadas, respeitando o gating intrusivo.

    Checagens intrusivas só entram quando ``config.intrusive`` é verdadeiro — é a
    trava técnica que impede varredura ativa sem autorização declarada.
    """
    selected: list[Checker] = []
    for cls in ALL_CHECKERS:
        if not config.wants(cls.id):
            continue
        if cls.intrusive and not config.intrusive:
            continue
        selected.append(cls())
    return selected


def all_check_metadata() -> list[tuple[str, str, str, bool]]:
    """(id, nome, categoria, intrusivo) de todas as checagens — para `sentinela checagens`."""
    return [(c.id, c.name, str(c.category), c.intrusive) for c in ALL_CHECKERS]
