"""Configuração de uma varredura."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinela.core.http import USER_AGENT


@dataclass(slots=True)
class ScanConfig:
    """Parâmetros que controlam o comportamento da varredura.

    ``intrusive`` é o interruptor ético central: checagens que enviam requisições
    além da leitura passiva de uma página (ex.: sondar rotas sensíveis) só rodam
    quando o operador declara explicitamente que tem autorização.
    """

    intrusive: bool = False
    discover: bool = False  # descoberta de subdomínios via Certificate Transparency (passiva, opt-in)
    timeout: float = 8.0  # servidor OK responde em <2s; teto baixo mantém a demo ágil
    user_agent: str = USER_AGENT
    verify_tls: bool = True
    skip: frozenset[str] = field(default_factory=frozenset)
    only: frozenset[str] = field(default_factory=frozenset)

    def wants(self, check_id: str) -> bool:
        """Decide se uma checagem deve rodar, respeitando ``only``/``skip``."""
        if self.only:
            return check_id in self.only
        return check_id not in self.skip
