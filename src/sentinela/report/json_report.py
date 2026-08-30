"""Renderizador JSON — saída legível por máquina (integração CI/CD, dashboards).

Contrato `suite-appsec/1`, comum às quatro ferramentas da suíte: CHAVES e VALORES de
identificador em inglês, TEXTO para humano em PT-BR. É a mesma regra que
`core.models` documenta no topo — este relatório era o único lugar que a desrespeitava,
emitindo chaves em português e severidades acentuadas (`"severidade": "Média"`), o que
obrigava um consumidor a manter uma tabela de-para só para a Sentinela.

`by_severity` traz SEMPRE as cinco chaves, inclusive zeradas: um dashboard que soma
`by_severity["critical"]` não pode quebrar por ausência de chave num relatório limpo.
"""

from __future__ import annotations

from sentinela.core.models import Finding, ScanResult
from sentinela.core.proveniencia import descobrir_commit, hash_do_catalogo, serializar_com_selo
from sentinela.knowledge.mapping import OWASP_EDICAO, tag_for
from sentinela.report._shared import SEVERITY_ORDER, score_of

SCHEMA = "suite-appsec/1"


def render_json(result: ScanResult) -> str:
    score = score_of(result)
    counts = result.counts_by_severity()
    payload: dict[str, object] = {
        "schema": SCHEMA,
        "tool": "sentinela",
        "version": result.tool_version,
        # Proveniência (ver `core.proveniencia`): `version` sozinho não vincula o laudo a
        # nada — "0.1.0" já nomeou dezenas de árvores. `commit` diz QUAL código rodou e
        # `ruleset_hash` diz QUAL catálogo; sem os dois, um reteste não distingue alvo
        # corrigido de regra alterada.
        "commit": descobrir_commit(),
        "ruleset_hash": hash_do_catalogo(),
        "owasp_edition": OWASP_EDICAO,
        "target": {
            "url": result.target.url,
            "host": result.target.host,
            "port": result.target.port,
            "scheme": result.target.scheme,
        },
        "mode": "intrusive" if result.intrusive else "non-intrusive",
        # Condições da máquina que rodou. Vários achados dependem delas, e sem este
        # carimbo dois relatórios divergentes do mesmo alvo eram indistinguíveis.
        "environment": result.ambiente,
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat() if result.finished_at else None,
        "duration_seconds": round(result.duration_seconds, 2),
        "checks_run": result.checks_run,
        "summary": {
            "total": len(result.findings),
            "by_severity": {sev.name.lower(): counts[sev] for sev in SEVERITY_ORDER},
            "score": {"value": score.value, "grade": score.grade, "text": score.summary},
        },
        "findings": [_finding_dict(f) for f in result.sorted_findings()],
        "errors": [{"check": e.check_id, "message": e.message} for e in result.errors],
    }
    # `artifact_sha256` entra por último e é calculado sobre o documento SEM ele — a
    # receita de verificação está no docstring de `serializar_com_selo`.
    return serializar_com_selo(payload)


def _finding_dict(finding: Finding) -> dict[str, object]:
    tag = tag_for(finding.id)
    return {
        "id": finding.id,
        "title": finding.title,
        "category": finding.category.value,
        # `severity` é identificador (EN, minúsculo); `severity_label` é o rótulo que o
        # relatório humano exibe; `severity_rank` permite ordenar sem tabela de-para.
        "severity": finding.severity.name.lower(),
        "severity_label": finding.severity.label,
        "severity_rank": int(finding.severity),
        # O que o achado AFIRMA (não confundir com severidade — ver FindingType) e o
        # quanto a checagem confia na própria afirmação. Default seguro quando a checagem
        # não declara: "observation"/"low", nunca "confirmed_vulnerability"/"high" por
        # omissão (core.models.Finding documenta o porquê).
        "type": finding.type.value,
        "confidence": finding.confidence.value,
        "subject": finding.subject,
        "owasp": tag.owasp if tag else None,
        "cwe": tag.cwe if tag else None,
        "cwe_name": tag.cwe_name if tag else None,
        "description": finding.description,
        "evidence": finding.evidence,
        "impact": finding.impact,
        "recommendation": finding.recommendation,
        "references": list(finding.references),
    }
