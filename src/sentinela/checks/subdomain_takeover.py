"""Descoberta de subdomínios e detecção de subdomain takeover (não-intrusiva).

Usa Certificate Transparency (dado público) para enumerar os subdomínios do alvo
e, para cada um, verifica se aponta (CNAME) para um serviço de terceiro
DESPROVISIONADO — o clássico *subdomain takeover*: o recurso (bucket S3, site
GitHub Pages, app Heroku…) foi apagado, mas o CNAME continuou apontando para lá.
Um atacante reivindica o recurso órfão e passa a servir conteúdo sob o SEU
domínio: phishing crível com o seu nome, roubo de cookies do domínio pai, bypass
de CORS/CSP que confiem no subdomínio.

Continua não-intrusiva: só lê dados públicos (CT, DNS) e as respostas que os
próprios ativos do alvo entregam. Roda apenas com ``--descobrir`` (consulta
serviço externo + resolve muitos nomes).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import dns.exception
import dns.resolver
import tldextract

from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.discovery import discover_subdomains
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
_DNS_TIMEOUT = 5.0
_MAX_CHECAR = 120  # limita a resolução de CNAME (o trabalho pesado) aos N primeiros


@dataclass(frozen=True, slots=True)
class _Servico:
    """Um serviço de terceiro passível de takeover e como reconhecê-lo."""

    nome: str
    cname_suffixes: tuple[str, ...]
    fingerprints: tuple[str, ...]  # marcadores no corpo indicando recurso não reivindicado
    nxdomain_takeover: bool  # se o CNAME-alvo em NXDOMAIN já basta para o takeover


# Curadoria a partir do projeto "can-i-take-over-xyz": apenas serviços com
# assinatura ESPECÍFICA (evita falso-positivo de 404 genérico).
# AWS S3 é tratado à parte: sob `amazonaws.com` há ELB/ALB/EC2/RDS/CloudFront que NÃO são
# reivindicáveis (o nome carrega um ID atribuído pela AWS). Só um ENDPOINT de bucket S3 é
# takeover-able. `_S3_MARK_RE` exige o marcador `.s3` seguido de `.`/`-` (cobre s3./s3-region/
# s3-website/s3.dualstack) e rejeita `.elb.`, `.compute.`, `.rds.`, etc.
_S3 = _Servico("AWS S3", (), ("NoSuchBucket", "The specified bucket does not exist"), False)
_S3_MARK_RE = re.compile(r"\.s3(?=[.-])", re.IGNORECASE)

_SERVICOS: tuple[_Servico, ...] = (
    _Servico("GitHub Pages", ("github.io",), ("There isn't a GitHub Pages site here",), False),
    _Servico(
        "Heroku",
        ("herokudns.com", "herokuapp.com", "herokussl.com"),
        ("No such app", "no-such-app.html"),
        False,
    ),
    _Servico("Fastly", ("fastly.net",), ("Fastly error: unknown domain",), False),
    _Servico("Shopify", ("myshopify.com",), ("Sorry, this shop is currently unavailable",), False),
    _Servico("Zendesk", ("zendesk.com",), ("Help Center Closed",), False),
    _Servico("Ghost", ("ghost.io",), ("The thing you were looking for is no longer here",), False),
    _Servico("Surge.sh", ("surge.sh",), ("project not found",), False),
    _Servico("Bitbucket", ("bitbucket.io",), ("Repository not found",), False),
    _Servico("Pantheon", ("pantheonsite.io",), ("The gods are wise",), False),
    _Servico(
        "Tumblr",
        ("domains.tumblr.com",),
        ("Whatever you were looking for doesn't currently exist",),
        False,
    ),
    _Servico(
        "Microsoft Azure",
        (
            "azurewebsites.net",
            "cloudapp.net",
            "cloudapp.azure.com",
            "trafficmanager.net",
            "blob.core.windows.net",
            "azureedge.net",
            "azure-api.net",
        ),
        (),
        True,
    ),
)


def _resolve_cname(host: str) -> str | None:
    """Alvo final do CNAME de ``host`` (minúsculo, sem ponto final), ou ``None``."""
    try:
        answer = dns.resolver.resolve(host, "CNAME", lifetime=_DNS_TIMEOUT)
    except dns.exception.DNSException:
        return None
    for rdata in answer:
        return str(rdata.target).rstrip(".").lower()
    return None


def _resolves(host: str) -> bool | None:
    """``True`` se resolve para A/AAAA, ``False`` se NXDOMAIN, ``None`` se inconclusivo."""
    for rt in ("A", "AAAA"):
        try:
            dns.resolver.resolve(host, rt, lifetime=_DNS_TIMEOUT)
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException:
            return None
    return False


def _match_servico(cname: str) -> _Servico | None:
    if cname.endswith(".amazonaws.com"):
        # Sob amazonaws.com, só um endpoint de bucket S3 é reivindicável; ELB/EC2/RDS/etc. não.
        return _S3 if _S3_MARK_RE.search(cname) else None
    for servico in _SERVICOS:
        if any(cname == s or cname.endswith("." + s) for s in servico.cname_suffixes):
            return servico
    return None


def _resolver_cnames(subs: list[str]) -> list[tuple[str, str]]:
    with ThreadPoolExecutor(max_workers=10) as pool:
        cnames = list(pool.map(_resolve_cname, subs))
    return [(sub, cname) for sub, cname in zip(subs, cnames, strict=True) if cname is not None]


class SubdomainTakeoverChecker(Checker):
    id = "subdomain-takeover"
    name = "Descoberta de subdomínios e subdomain takeover"
    category = Category.SURFACE
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        if not ctx.config.discover:
            return
        host = ctx.target.host
        if _is_ip(host):
            return
        domain = self._registrable(host)
        if not domain:
            return

        subdominios = discover_subdomains(domain)
        if subdominios is None:
            return  # crt.sh inconclusivo — não afirmar nada

        if subdominios:
            yield self._superficie(domain, subdominios)

        for sub, cname in _resolver_cnames(subdominios[:_MAX_CHECAR]):
            servico = _match_servico(cname)
            if servico is not None:
                yield from self._avaliar(ctx, sub, cname, servico)

    def _superficie(self, domain: str, subdominios: list[str]) -> Finding:
        amostra = subdominios[:15]
        resto = f" (+{len(subdominios) - len(amostra)} outros)" if len(subdominios) > len(amostra) else ""
        return Finding(
            id="SUPERFICIE_SUBDOMINIOS",
            title=f"Superfície: {len(subdominios)} subdomínio(s) descobertos",
            category=self.category,
            severity=Severity.INFO,
            description=(
                f"O Certificate Transparency revela {len(subdominios)} nome(s) sob `{domain}`. "
                "Cada um é uma porta de entrada a ser mantida e protegida."
            ),
            evidence=", ".join(amostra) + resto,
            impact=(
                "Subdomínios esquecidos (ambientes de teste, integrações antigas, painéis) costumam "
                "ficar sem hardening e são o caminho preferido do atacante. Você só protege o que "
                "sabe que existe."
            ),
            recommendation=(
                "Inventarie os subdomínios, desative os que não usa e garanta que a remoção de um "
                "ativo remova também o registro DNS (evita subdomain takeover)."
            ),
            references=(ref.CRT_SH, ref.OWASP_WSTG_SUBDOMAIN),
        )

    def _avaliar(self, ctx: ScanContext, sub: str, cname: str, servico: _Servico) -> Iterable[Finding]:
        if servico.nxdomain_takeover:
            if _resolves(cname) is False:
                yield self._takeover(
                    sub, cname, servico, f"o alvo do CNAME (`{cname}`) não existe mais (NXDOMAIN)"
                )
            return

        probe = None
        for scheme in ("https", "http"):
            candidato = ctx.client.get(f"{scheme}://{sub}/")
            if candidato.ok:
                probe = candidato
                break

        if probe is None:
            # Sem resposta HTTP e sem assinatura confirmada: é higiene de DNS (CNAME órfão a
            # verificar), NÃO um takeover confirmado — INFO, não penaliza a nota. Um recurso
            # realmente reivindicável (ex.: bucket S3 órfão) responderia com a assinatura e cairia
            # no ramo CRÍTICO abaixo.
            yield Finding(
                id="SUBDOMAIN_TAKEOVER_POSSIVEL",
                title=f"CNAME órfão a verificar: {sub}",
                category=self.category,
                severity=Severity.INFO,
                description=(
                    f"`{sub}` aponta (CNAME) para {servico.nome} (`{cname}`) mas não respondeu. "
                    "Pode ser um CNAME órfão — vale verificar manualmente se o recurso ainda é seu."
                ),
                evidence=f"{sub} → {cname}",
                impact=(
                    "Um CNAME apontando para um recurso de terceiro que não responde pode indicar "
                    "um recurso desprovisionado. Se o serviço permitir reivindicar o nome, vira "
                    "subdomain takeover; caso contrário, é apenas higiene de DNS."
                ),
                recommendation=(
                    f"Confirme se o recurso em {servico.nome} ainda é seu. Se não for mais usado, "
                    "remova o registro CNAME para evitar risco futuro."
                ),
                references=(ref.OWASP_WSTG_SUBDOMAIN,),
            )
            return

        corpo = probe.body_snippet.lower()
        if any(fp.lower() in corpo for fp in servico.fingerprints):
            yield self._takeover(
                sub,
                cname,
                servico,
                f"a resposta contém a assinatura de recurso não reivindicado de {servico.nome}",
            )

    def _takeover(self, sub: str, cname: str, servico: _Servico, motivo: str) -> Finding:
        return Finding(
            id="SUBDOMAIN_TAKEOVER",
            title=f"Subdomain takeover: {sub}",
            category=self.category,
            severity=Severity.CRITICAL,
            description=(
                f"`{sub}` aponta (CNAME) para {servico.nome} (`{cname}`), mas {motivo} — condição "
                "clássica de subdomain takeover."
            ),
            evidence=f"{sub} → {cname}",
            impact=(
                "Um atacante pode reivindicar o recurso órfão e passar a servir QUALQUER conteúdo "
                f"sob `{sub}`: página de phishing crível com o seu domínio, roubo de cookies do "
                "domínio pai, bypass de CORS/CSP que confiem no subdomínio e dano de reputação."
            ),
            recommendation=(
                f"Remova IMEDIATAMENTE o registro CNAME de `{sub}` OU reivindique novamente o recurso "
                f"em {servico.nome}. Depois, revise todos os subdomínios que apontam para serviços "
                "de terceiros."
            ),
            references=(ref.OWASP_WSTG_SUBDOMAIN,),
        )

    def _registrable(self, host: str) -> str | None:
        ext = _EXTRACT(host)
        top = getattr(ext, "top_domain_under_public_suffix", None)
        if top is not None:
            return top or None
        return ext.registered_domain or None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
