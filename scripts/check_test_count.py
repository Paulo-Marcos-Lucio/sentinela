#!/usr/bin/env python3
"""Portão de contagem de testes: badge GERADO, não digitado.

A auditoria cruzada da suíte (2026-09-12, classe C) encontrou o mesmo defeito em três das
quatro ferramentas: o número de testes no README era um literal digitado à mão que envelhecia
em silêncio (a Sentinela dizia "351"/"522" enquanto rodavam 472/668). A esteira era o único
contra-exemplo — batia exato — porque a diferença entre um número que mente e um que não mente
é EXISTIR um portão que o compara com a realidade.

Este script é esse portão. Ele coleta a verdade com ``pytest --collect-only`` e a confronta com
TODA contagem exibida ao leitor: o badge (SVG do chip ou shields.io), o texto alternativo do
badge e a prosa dos READMEs (PT e EN). Diverge em um único lugar → sai com código 1.

Invariante fechada: *o número de testes mostrado ao público == ``pytest --collect-only``*.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent

# Arquivos que exibem a contagem ao leitor. Os que não existirem numa dada branch são pulados
# (o README em inglês e o SVG do chip são opcionais; a edição Pro usa badge shields.io).
ARQUIVOS_COM_CONTAGEM = ("README.md", "README.en.md", "assets/chip-tests.svg")

# Cada padrão captura, no grupo 1, um número que é APRESENTADO como a contagem de testes.
# Cobrir as duas famílias de badge que a suíte usa (chip SVG e shields.io) + a prosa PT/EN.
_PADROES = (
    re.compile(r"tests-(\d+)(?:%20|\s)+passing", re.IGNORECASE),  # shields.io: tests-668%20passing
    re.compile(r"(\d+)\s+tests?\s+passing", re.IGNORECASE),  # alt-text do chip / texto do SVG
    re.compile(r"(\d+)\s+testes\s+\(inclu", re.IGNORECASE),  # prosa PT: "472 testes (incluindo"
    re.compile(r"(\d+)\s+tests\s+\(inclu", re.IGNORECASE),  # prosa EN: "472 tests (including"
)


def _coletados() -> int:
    """Quantos testes o ``pytest`` coleta AGORA — a única fonte de verdade."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "--no-cov"],
        capture_output=True,
        text=True,
        cwd=RAIZ,
        check=False,
    )
    m = re.search(r"(\d+)\s+tests?\s+collected", proc.stdout)
    if not m:
        sys.stderr.write(
            "check_test_count: pytest --collect-only não devolveu uma contagem.\n"
            "Saída (fim):\n" + (proc.stdout or proc.stderr)[-2000:] + "\n"
        )
        raise SystemExit(2)
    return int(m.group(1))


def _declarados() -> list[tuple[str, int]]:
    """Toda contagem EXIBIDA, como pares (arquivo, número)."""
    achados: list[tuple[str, int]] = []
    for rel in ARQUIVOS_COM_CONTAGEM:
        caminho = RAIZ / rel
        if not caminho.exists():
            continue
        texto = caminho.read_text(encoding="utf-8")
        for padrao in _PADROES:
            for m in padrao.finditer(texto):
                achados.append((rel, int(m.group(1))))
    return achados


def main() -> int:
    real = _coletados()
    declarados = _declarados()

    if not declarados:
        sys.stderr.write(
            "check_test_count: nenhuma contagem de testes encontrada nos arquivos de vitrine "
            f"({', '.join(ARQUIVOS_COM_CONTAGEM)}). O badge não pode ser verificado.\n"
        )
        return 1

    divergentes = [(arq, n) for (arq, n) in declarados if n != real]
    if divergentes:
        sys.stderr.write(
            f"check_test_count: pytest coleta {real} testes, mas a vitrine exibe outro número:\n"
        )
        for arq, n in divergentes:
            sys.stderr.write(f"  - {arq}: exibe {n} (esperado {real})\n")
        sys.stderr.write(
            "Corrija o número exibido (badge + prosa) para bater com --collect-only "
            "— o badge é gerado, não digitado.\n"
        )
        return 1

    print(f"check_test_count: OK — {real} testes coletados, {len(declarados)} exibição(ões) conferem.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
