"""Contrato base de uma checagem."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import ClassVar

from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding


class Checker(ABC):
    """Uma checagem de segurança independente.

    Subclasses declaram os metadados como atributos de classe e implementam
    :meth:`run`, que recebe o :class:`ScanContext` e produz achados. Uma checagem
    **nunca** deve levantar exceção por falha de rede: o motor captura exceções,
    mas o esperado é que a checagem trate o caso e simplesmente não gere achados
    (ou gere um achado informativo) quando não conseguir avaliar.
    """

    id: ClassVar[str]
    name: ClassVar[str]
    category: ClassVar[Category]
    intrusive: ClassVar[bool] = False

    @abstractmethod
    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        """Executa a checagem e devolve os achados encontrados."""
        raise NotImplementedError
