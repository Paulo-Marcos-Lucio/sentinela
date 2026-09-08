"""Cobertura da varredura — o que rodou, o que não, e por quê.

Fonte ÚNICA da resposta a "esta varredura olhou o alvo inteiro?". Existe porque a
nota respondia como se sempre tivesse olhado: com ``--somente securityheaders`` ou
``--perfil rapido`` o mesmo alvo passava de F/exit 1 para A/exit 0 sem uma linha
dizendo que 3, 9 checagens tinham ficado de fora (achado 1.2 da auditoria 2026-09-07).

A distinção que sustenta tudo: nem toda omissão é uma lacuna.

* **Por seleção do operador** (``--somente``/``--pular``/``--perfil rapido``) — o operador
  reduziu a cobertura base. ISSO torna a varredura PARCIAL: teta o conceito (parcial não
  tira A) e o resumo nomeia o que faltou. É o buraco que o achado descreve.
* **Por modo** (checagem intrusiva sem ``--autorizado``) — é o DESENHO do modo
  não-intrusivo, não uma falha. Se contasse como lacuna, nenhuma varredura padrão tiraria
  A. Então é declarada (transparência: "não sondei rotas sensíveis"), mas não teta.
* **Por erro** (a checagem rodou e falhou) — não medimos aquilo. Conta como parcial: uma
  ausência de achado ali não é prova de ausência de problema.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from sentinela.core.config import ScanConfig
from sentinela.core.models import ScanError

MOTIVO_OPERADOR = "seleção do operador (--somente/--pular/--perfil rapido)"
MOTIVO_MODO = "requer modo autorizado (--autorizado)"
MOTIVO_ERRO = "falhou durante a execução"


@dataclass(frozen=True, slots=True)
class Coverage:
    """Retrato do que a varredura de fato cobriu."""

    executadas: tuple[str, ...]
    por_operador: tuple[str, ...]
    """Checagens da base do modo que o operador desligou (--somente/--pular/--perfil)."""
    por_modo: tuple[str, ...]
    """Checagens intrusivas puladas por o modo ser não-intrusivo — desenho, não lacuna."""
    por_erro: tuple[str, ...]
    """Checagens que rodaram e falharam — o alvo delas ficou sem veredito."""

    @property
    def parcial(self) -> bool:
        """A cobertura BASE do modo foi reduzida por escolha do operador ou por falha.

        Omissão intrusiva-por-modo NÃO conta: é o modo não-intrusivo funcionando como
        projetado, e fazê-la tetar puniria toda varredura padrão.
        """
        return bool(self.por_operador or self.por_erro)

    @property
    def base_total(self) -> int:
        """Denominador honesto: quantas checagens comporiam a cobertura plena deste modo."""
        return len(self.executadas) + len(self.por_operador) + len(self.por_erro)

    @property
    def plena(self) -> bool:
        return not self.parcial

    def resumo_omissoes(self) -> str:
        """Uma frase nomeando o que ficou de fora — para o resumo do laudo."""
        partes: list[str] = []
        if self.por_operador:
            partes.append(f"{', '.join(self.por_operador)} ({MOTIVO_OPERADOR})")
        if self.por_erro:
            partes.append(f"{', '.join(self.por_erro)} ({MOTIVO_ERRO})")
        return "; ".join(partes)


def compute_coverage(
    config: ScanConfig,
    checks_run: Iterable[str],
    errors: Iterable[ScanError],
    *,
    todos: Iterable[tuple[str, bool]] | None = None,
) -> Coverage:
    """Deriva a cobertura de uma varredura.

    ``todos`` é a lista ``(check_id, intrusiva)`` de TODAS as checagens do registro; quando
    omitido, é lida do registro. Injetável para teste sem montar o registro inteiro.
    """
    if todos is None:
        from sentinela.core.registry import ALL_CHECKERS

        todos = [(c.id, c.intrusive) for c in ALL_CHECKERS]

    executadas = tuple(checks_run)
    exec_set = set(executadas)
    err_ids = {e.check_id for e in errors}

    base_ids: list[str] = []
    por_modo: list[str] = []
    for cid, intrusiva in todos:
        if intrusiva and not config.intrusive:
            por_modo.append(cid)
        else:
            base_ids.append(cid)

    por_erro = tuple(cid for cid in base_ids if cid in err_ids)
    por_operador = tuple(cid for cid in base_ids if cid not in exec_set and cid not in err_ids)

    return Coverage(
        executadas=executadas,
        por_operador=por_operador,
        por_modo=tuple(por_modo),
        por_erro=por_erro,
    )
