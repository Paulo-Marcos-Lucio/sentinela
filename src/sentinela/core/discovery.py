"""Descoberta passiva de subdomínios via Certificate Transparency.

Todo certificado TLS emitido é registrado nos logs públicos de Certificate
Transparency — consultáveis por qualquer um, SEM tocar no alvo. É o ponto de
partida de qualquer avaliação externa séria: revela a superfície real (todos os
nomes para os quais já se emitiu certificado), quase sempre maior do que o dono
imagina.

Duas fontes públicas, com tolerância a falha: a API do Cert Spotter (SSLMate)
como primária (JSON estruturado e estável) e o crt.sh como fallback. Se ambas
falharem, a descoberta é inconclusiva (``None``) — nunca se afirma nada. Fica
atrás do flag ``--descobrir`` por consultar serviço externo e ser mais lenta.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from sentinela.core.http import HttpClient

_CERTSPOTTER = (
    "https://api.certspotter.com/v1/issuances"
    "?domain={domain}&include_subdomains=true&expand=dns_names"
)
_CRTSH = "https://crt.sh/?q=%25.{domain}&output=json"
_TIMEOUT = 30.0  # essas fontes costumam ser lentas; teto próprio, sem afetar o resto da varredura
_BODY_CAP = 8_000_000
_MAX_SUBDOMINIOS = 300


def discover_subdomains(domain: str) -> list[str] | None:
    """Nomes distintos sob ``domain`` conhecidos pelo Certificate Transparency.

    Tenta Cert Spotter e cai para o crt.sh. ``None`` = ambas falharam
    (inconclusivo). Lista (possivelmente vazia) = consulta OK. Nunca levanta exceção.
    """
    raw = _fetch(_CERTSPOTTER.format(domain=domain))
    if raw is not None:
        nomes = _parse_certspotter(raw, domain)
        if nomes is not None:
            return nomes
    raw = _fetch(_CRTSH.format(domain=domain))
    if raw is not None:
        return _parse_crtsh(raw, domain)
    return None


def _fetch(url: str) -> str | None:
    with HttpClient(timeout=_TIMEOUT, max_body_bytes=_BODY_CAP) as client:
        probe = client.get(url)
    if probe.ok and probe.status_code == 200 and probe.body_snippet:
        return probe.body_snippet
    return None


def _load_list(raw: str) -> list[object] | None:
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return None  # JSON truncado/inválido → inconclusivo
    return data if isinstance(data, list) else None


def _parse_certspotter(raw: str, domain: str) -> list[str] | None:
    registros = _load_list(raw)
    if registros is None:
        return None
    candidatos: list[str] = []
    for reg in registros:
        if isinstance(reg, dict):
            nomes = reg.get("dns_names") or []
            if isinstance(nomes, list):
                candidatos.extend(str(n) for n in nomes)
    return _filtrar(candidatos, domain)


def _parse_crtsh(raw: str, domain: str) -> list[str] | None:
    registros = _load_list(raw)
    if registros is None:
        return None
    candidatos: list[str] = []
    for reg in registros:
        if isinstance(reg, dict):
            candidatos.extend(str(reg.get("name_value", "")).splitlines())
    return _filtrar(candidatos, domain)


def _filtrar(candidatos: Iterable[str], domain: str) -> list[str]:
    dom = domain.lower()
    suffix = "." + dom
    nomes: set[str] = set()
    for bruto in candidatos:
        nome = bruto.strip().lower().lstrip("*.").rstrip(".")
        if not nome or "*" in nome:
            continue
        if nome == dom or nome.endswith(suffix):
            nomes.add(nome)
    return sorted(nomes)[:_MAX_SUBDOMINIOS]
