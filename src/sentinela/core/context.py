"""Contexto compartilhado passado a cada checagem."""

from __future__ import annotations

from dataclasses import dataclass

from sentinela.core.config import ScanConfig
from sentinela.core.http import HttpClient, Probe
from sentinela.core.models import Target


@dataclass(slots=True)
class ScanContext:
    """Tudo que uma checagem precisa para trabalhar.

    O motor coleta as respostas "primárias" uma única vez e as compartilha, para
    que dez checagens de cabeçalho não disparem dez requisições idênticas.
    """

    target: Target
    client: HttpClient
    config: ScanConfig
    primary: Probe
    """GET do alvo (seguindo redirecionamentos) — a resposta principal."""

    http_probe: Probe | None = None
    """GET de ``http://host`` SEM seguir redirecionamento, p/ avaliar upgrade a HTTPS."""
