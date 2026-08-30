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

    avaliar_cabecalhos: bool = True
    """A resposta primária é DE FATO uma resposta servida pelo alvo (2xx), não uma página
    de bloqueio de WAF/CDN nem um erro. Quando falso, nenhuma checagem pode AFIRMAR
    ausência de cabeçalho/cookie/método a partir dessa resposta — seria auditar o objeto
    errado (a página do WAF, não o site). É o irmão de :attr:`Probe.corpo_confiavel`,
    um degrau acima: lá a pergunta é "o corpo veio inteiro?"; aqui é "este corpo é do alvo?"."""

    avaliar_documento: bool = True
    """A resposta primária é um DOCUMENTO HTML do alvo. Quando falso (JSON, CSS, imagem),
    as políticas de DOCUMENTO — CSP, anti-clickjacking, Referrer-Policy, Permissions-Policy,
    COOP — não se aplicam (MDN): cobrá-las de um `application/json` é falso positivo. As
    checagens de TRANSPORTE (HSTS, nosniff, cookies, CORS, métodos) seguem valendo."""
