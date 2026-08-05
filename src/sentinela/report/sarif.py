"""Renderizador SARIF 2.1.0 — saída padrão para ingestão em ferramentas.

A Sentinela é um scanner de *postura* (observa um alvo web em execução), não um
analisador de código-fonte: os achados não têm arquivo/linha, então cada resultado é
localizado pela **URL do alvo** — ou, quando o achado é sobre um ativo específico
(um subdomínio), pela URL desse ativo. O documento é válido contra o schema SARIF
2.1.0 e pode ser consumido por pipelines, dashboards ou enviado à aba *Security* do
GitHub via `upload-sarif`.
"""

from __future__ import annotations

import hashlib
import json

from sentinela.core.models import Finding, ScanResult, Severity
from sentinela.core.proveniencia import descobrir_commit, hash_do_catalogo
from sentinela.knowledge.mapping import OWASP_EDICAO, tag_for

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

# Texto ESTÁVEL do descritor de regra, para os achados que podem sair várias vezes numa
# varredura com o mesmo id. `rules[]` é o CATÁLOGO de tipos de problema: pôr ali o
# hostname de UMA vítima (escolhido por ordem alfabética, por acaso) polui o dashboard e
# muda o nome da regra a cada execução. O dado da instância vive no `result`.
_REGRA_ESTAVEL: dict[str, tuple[str, str]] = {
    "SUBDOMAIN_TAKEOVER": (
        "Subdomain takeover",
        "Um subdomínio aponta (CNAME) para um recurso de terceiro desprovisionado — "
        "um atacante pode reivindicá-lo e servir conteúdo sob o domínio do alvo.",
    ),
    "SUBDOMAIN_TAKEOVER_POSSIVEL": (
        "CNAME órfão a verificar",
        "Um subdomínio aponta (CNAME) para um serviço de terceiro que não respondeu — "
        "pode indicar recurso desprovisionado.",
    ),
}


def _fingerprint(finding: Finding) -> str:
    """Identidade da INSTÂNCIA, estável entre varreduras.

    O GitHub usa `partialFingerprints` para decidir se dois resultados são "logicamente
    idênticos" — e para casar alertas ENTRE execuções. Antes, o valor era o próprio
    `finding.id`: três subdomain takeovers CRÍTICOS distintos viravam um alerta só, e o
    cliente corrigia um achando que tinha acabado.

    A `evidence` seria o campo óbvio para distinguir, mas é volátil: um nonce rotativo na
    CSP ou um cookie novo mudariam o hash e o GitHub fecharia o alerta e abriria outro a
    cada varredura. `subject` (o ativo) distingue sem oscilar; na sua ausência, o título,
    que é constante em toda checagem agregada.
    """
    bruto = f"{finding.id}|{finding.subject or finding.title}".encode()
    return hashlib.sha256(bruto).hexdigest()[:16]


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
            properties["owasp_edition"] = OWASP_EDICAO

        titulo, descricao = _REGRA_ESTAVEL.get(finding.id, (finding.title, finding.description))
        descriptor: dict[str, object] = {
            "id": finding.id,
            "name": finding.id,  # identificador opaco e estável, nunca dado de instância
            "shortDescription": {"text": titulo},
            "fullDescription": {"text": descricao or titulo},
            "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
            "properties": properties,
        }
        if finding.references:
            descriptor["helpUri"] = finding.references[0]
        descriptors.append(descriptor)
    return descriptors


def _location(finding: Finding, target_url: str) -> str:
    """URI do ativo a que o achado se refere — o alvo, ou o subdomínio quando houver.

    Sem isto, três takeovers em hosts diferentes apontam todos para a URL do alvo e o
    consumidor não sabe ONDE agir, mesmo com fingerprints distintos.
    """
    if finding.subject and "/" not in finding.subject:
        return f"https://{finding.subject}/"
    return target_url


def _result(finding: Finding, target_url: str) -> dict[str, object]:
    partes = [finding.title, finding.evidence, finding.recommendation]
    message = " — ".join(p for p in partes if p)
    properties = {
        chave: valor
        for chave, valor in (
            ("evidence", finding.evidence),
            ("impact", finding.impact),
            ("subject", finding.subject),
        )
        if valor
    }
    return {
        "ruleId": finding.id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": _location(finding, target_url)}}}],
        "partialFingerprints": {"sentinelaFindingId/v1": _fingerprint(finding)},
        "properties": properties,
    }


def render_sarif(result: ScanResult) -> str:
    """Serializa o resultado da varredura como um documento SARIF 2.1.0."""
    findings = result.sorted_findings()
    # Proveniência também no SARIF (o que sobe pro Code Scanning): ruleset_hash nas
    # properties do run, e o commit no slot padrão `versionControlProvenance` quando
    # conhecido — sem isso, um alerta no GitHub não se vincula ao código/catálogo que o gerou.
    commit = descobrir_commit()
    run: dict[str, object] = {
        "tool": {
            "driver": {
                "name": "sentinela",
                "informationUri": "https://github.com/Paulo-Marcos-Lucio/sentinela",
                "version": result.tool_version,
                "rules": _rule_descriptors(findings),
            }
        },
        "properties": {"owasp_edition": OWASP_EDICAO, "ruleset_hash": hash_do_catalogo()},
        "results": [_result(f, result.target.url) for f in findings],
    }
    if commit is not None:
        run["versionControlProvenance"] = [{"revisionId": commit}]
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)
