"""Utilidades compartilhadas pelos renderizadores de relatório."""

from __future__ import annotations

from sentinela.core.models import Category, Finding, ScanResult, Severity
from sentinela.core.scoring import Score, compute_score

SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


def score_of(result: ScanResult) -> Score:
    return compute_score(result.findings)


def ordered_counts(result: ScanResult) -> list[tuple[Severity, int]]:
    """Contagem por severidade, da mais grave à menos grave."""
    counts = result.counts_by_severity()
    return [(sev, counts[sev]) for sev in SEVERITY_ORDER]


def grouped_by_category(findings: list[Finding]) -> dict[Category, list[Finding]]:
    """Agrupa os achados por categoria, ordenando por severidade dentro do grupo."""
    grupos: dict[Category, list[Finding]] = {}
    for finding in findings:
        grupos.setdefault(finding.category, []).append(finding)
    for lista in grupos.values():
        lista.sort(key=lambda f: (-int(f.severity), f.title))
    # Ordena as categorias pela severidade máxima que contêm.
    return dict(
        sorted(
            grupos.items(),
            key=lambda kv: -max(int(f.severity) for f in kv[1]),
        )
    )
