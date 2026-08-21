"""Contexto compartilhado passado a cada checagem."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinela.core.config import ScanConfig
from sentinela.core.http import HttpClient, Probe
from sentinela.core.models import CheckSkip, Target


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

    skipped: list[CheckSkip] = field(default_factory=list)
    """Checagens que concluíram, de propósito, que não dava para avaliar desta vez.

    Uma ÚNICA instância de :class:`ScanContext` é compartilhada por todas as
    checagens de uma varredura (``core.engine.run_scan`` cria uma e passa a mesma
    referência para cada ``Checker.run``) — por isso ``append`` aqui, e não um
    retorno próprio por checagem. O motor lê esta lista inteira só depois que o
    `ThreadPoolExecutor` da varredura termina, quando todas as threads que
    poderiam ter chamado ``append`` já se juntaram; `list.append` é atômico sob o
    GIL, então não precisa de lock para essa janela de escrita concorrente.
    """
