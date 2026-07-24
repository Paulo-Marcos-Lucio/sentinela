"""Renderizador SARIF 2.1.0 — saída padrão para ingestão em ferramentas.

A Sentinela é um scanner de *postura* (observa um alvo web em execução), não um
analisador de código-fonte: os achados não têm arquivo/linha, então cada
resultado é localizado pela **URL do alvo**. O documento é válido contra o
schema SARIF 2.1.0 e pode ser consumido por pipelines, dashboards ou enviado à
aba *Security* do GitHub via `upload-sarif`.
"""

from __future__ import annotations

import json

from sentinela.core.models import Finding, ScanResult, Severity
from sentinela.knowledge.mapping import tag_for

# Nível SARIF por severidade (o vocabulário do SARIF tem só 4 níveis).
_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# `security-severity` (0–10) é a convenção que o GitHub usa para ordenar achados.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _rule_descriptors(findings: list[Finding]) -> list[dict[str, object]]:
    """Um descritor por ID de achado presente (deduplicado, ordem estável)."""
    seen: dict[str, Finding] = {}
    for finding in findings:
        seen.setdefault(finding.id, finding)

    descriptors: list[dict[str, object]] = []
    for finding in seen.values():
        tag = tag_for(finding.id)
        properties: dict[str, object] = {
            "tags": ["security", finding.category.value],
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        }
        if tag and tag.cwe:
            properties["cwe"] = tag.cwe
        if tag and tag.owasp:
            properties["owasp"] = tag.owasp

        descriptor: dict[str, object] = {
            "id": finding.id,
            "name": finding.title,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.description or finding.title},
            "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
            "properties": properties,
        }
        if finding.references:
            descriptor["helpUri"] = finding.references[0]
        descriptors.append(descriptor)
    return descriptors


def _result(finding: Finding, target_url: str) -> dict[str, object]:
    message = finding.title
    if finding.recommendation:
        message = f"{finding.title} — {finding.recommendation}"
    return {
        "ruleId": finding.id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": target_url}}}],
        "partialFingerprints": {"sentinelaFindingId/v1": finding.id},
    }


def render_sarif(result: ScanResult) -> str:
    """Serializa o resultado da varredura como um documento SARIF 2.1.0."""
    findings = result.sorted_findings()
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sentinela",
                        "informationUri": "https://github.com/Paulo-Marcos-Lucio/sentinela",
                        "version": result.tool_version,
                        "rules": _rule_descriptors(findings),
                    }
                },
                "results": [_result(f, result.target.url) for f in findings],
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)
