"""Higiene de DNS e segurança de e-mail (SPF, DMARC, CAA, DNSSEC).

Todas as checagens são consultas DNS públicas — não-intrusivas. Trabalham sobre
o *domínio registrável* (eTLD+1), resolvido pela Public Suffix List, para tratar
corretamente domínios como ``empresa.com.br``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

import dns.exception
import dns.rdatatype
import dns.resolver

from sentinela.checks._util import is_ip, is_provider_hosted, registrable
from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

_DNS_TIMEOUT = 5.0


def _resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = _DNS_TIMEOUT
    resolver.lifetime = _DNS_TIMEOUT
    return resolver


def _txt_records(resolver: dns.resolver.Resolver, name: str) -> list[str] | None:
    """TXT do nome. ``[]`` = consulta OK e sem registro (ausência REAL); ``None`` = a consulta
    FALHOU (timeout/SERVFAIL/NoNameservers) → inconclusivo, não se pode afirmar ausência."""
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return []  # resolveu, mas não há registro → ausência real
    except dns.exception.DNSException:
        return None  # timeout/SERVFAIL/etc. → NÃO afirmar 'ausente' (acurácia de campo)
    records: list[str] = []
    for rdata in answer:
        # Junta os fragmentos de uma string TXT longa.
        parts = b"".join(rdata.strings) if hasattr(rdata, "strings") else b""
        records.append(parts.decode("utf-8", "replace"))
    return records


class DnsEmailChecker(Checker):
    id = "dns-email"
    name = "DNS e segurança de e-mail"
    category = Category.DNS_EMAIL
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        host = ctx.target.host
        if is_ip(host):
            return  # alvo é IP puro; checagens de domínio não se aplicam

        domain = registrable(host)
        if not domain:
            return

        if is_provider_hosted(host):
            yield Finding(
                id="DNS_HOSPEDAGEM_GERENCIADA",
                title="Domínio em hospedagem gerenciada (DNS/e-mail do provedor)",
                category=self.category,
                severity=Severity.INFO,
                description=(
                    f"`{domain}` está sob hospedagem gerenciada — o dono do site não controla o "
                    "DNS do apex nem envia e-mail por esse nome."
                ),
                impact=(
                    "Checagens de SPF/DMARC/CAA/DNSSEC não se aplicam (ou não são acionáveis) aqui: "
                    "elas pertencem ao provedor, não a você. Puladas para não gerar achado enganoso."
                ),
                recommendation=(
                    "Para postura de e-mail/DNS, rode a Sentinela contra o seu DOMÍNIO PRÓPRIO "
                    "(ex.: empresa.com.br), não contra a URL de páginas do provedor."
                ),
                references=(ref.DMARC_ORG,),
            )
            return

        resolver = _resolver()
        yield from self._check_spf(resolver, domain)
        yield from self._check_dmarc(resolver, domain)
        yield from self._check_caa(resolver, domain)
        yield from self._check_dnssec(resolver, domain)
        # MTA-STS/TLS-RPT só fazem sentido se o domínio RECEBE e-mail (tem MX). Sem
        # MX confirmado, não afirmamos ausência — evita achado enganoso em domínio
        # que não trata e-mail por esse nome.
        if self._has_mx(resolver, domain):
            yield from self._check_mta_sts(resolver, domain)
            yield from self._check_tls_rpt(resolver, domain)

    def _check_spf(self, resolver: dns.resolver.Resolver, domain: str) -> Iterable[Finding]:
        txt = _txt_records(resolver, domain)
        if txt is None:
            return  # consulta inconclusiva — não afirmar SPF ausente
        spf = [r for r in txt if r.lower().startswith("v=spf1")]
        if not spf:
            yield Finding(
                id="SPF_AUSENTE",
                title="Registro SPF ausente",
                category=self.category,
                severity=Severity.MEDIUM,
                description=f"O domínio `{domain}` não publica um registro SPF.",
                impact=(
                    "Sem SPF, qualquer servidor pode enviar e-mails se passando pelo "
                    "seu domínio, facilitando phishing e fraude contra seus clientes."
                ),
                recommendation=(
                    "Publique um registro SPF autorizando apenas os servidores de "
                    "envio legítimos e finalizando com `-all`, ex.: "
                    "`v=spf1 include:_spf.provedor.com -all`."
                ),
                references=(ref.RFC_SPF, ref.DMARC_ORG),
            )
            return

        record = spf[0]
        lowered = record.lower()
        # Permissivo = não termina de forma restritiva. Sem `-all` (hardfail) nem
        # `~all` (softfail), a ausência de mecanismo `all` equivale ao default
        # neutro `?all` (RFC 7208), que autoriza qualquer remetente.
        if "-all" not in lowered and "~all" not in lowered:
            yield Finding(
                id="SPF_PERMISSIVO",
                title="Registro SPF permissivo",
                category=self.category,
                severity=Severity.LOW,
                description="O SPF existe, mas não restringe os remetentes de forma efetiva.",
                evidence=record,
                impact="Um SPF com `+all` (ou sem `-all`/`~all`) autoriza qualquer remetente, anulando a proteção.",
                recommendation="Finalize o SPF com `-all` (hardfail) para rejeitar remetentes não autorizados.",
                references=(ref.RFC_SPF,),
            )

    def _check_dmarc(self, resolver: dns.resolver.Resolver, domain: str) -> Iterable[Finding]:
        txt = _txt_records(resolver, f"_dmarc.{domain}")
        if txt is None:
            return  # consulta inconclusiva — não afirmar DMARC ausente
        records = [r for r in txt if r.lower().startswith("v=dmarc1")]
        if not records:
            yield Finding(
                id="DMARC_AUSENTE",
                title="Registro DMARC ausente",
                category=self.category,
                severity=Severity.MEDIUM,
                description=f"O domínio `{domain}` não publica uma política DMARC.",
                impact=(
                    "Sem DMARC, mesmo com SPF/DKIM os provedores não sabem o que fazer "
                    "com e-mails que falham na autenticação, deixando brecha para spoofing."
                ),
                recommendation=(
                    "Publique um registro em `_dmarc.<domínio>` começando por monitoramento "
                    "(`v=DMARC1; p=none; rua=mailto:...`) e evolua para `p=quarantine` e `p=reject`."
                ),
                references=(ref.RFC_DMARC, ref.DMARC_ORG),
            )
            return

        record = records[0]
        # Extrai o valor exato do tag `p=` (a política principal). Substring ingênua
        # casaria `p=none` dentro de `sp=none` (política de subdomínio) — falso-positivo.
        policy_match = re.search(r"(?:^|;)\s*p\s*=\s*(\w+)", record, re.IGNORECASE)
        policy = policy_match.group(1).lower() if policy_match else ""
        if policy == "none":
            yield Finding(
                id="DMARC_SEM_ENFORCEMENT",
                title="DMARC apenas em modo monitoramento",
                category=self.category,
                severity=Severity.LOW,
                description="A política DMARC está em `p=none` (só monitora, não bloqueia).",
                evidence=record,
                impact="Em `p=none`, e-mails falsificados ainda são entregues; a proteção efetiva não está ativa.",
                recommendation="Após analisar os relatórios, evolua a política para `p=quarantine` e depois `p=reject`.",
                references=(ref.RFC_DMARC, ref.DMARC_ORG),
            )

    def _check_caa(self, resolver: dns.resolver.Resolver, domain: str) -> Iterable[Finding]:
        try:
            resolver.resolve(domain, "CAA")
            return  # possui CAA — ok
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException:
            return  # inconclusivo (timeout etc.)
        yield Finding(
            id="CAA_AUSENTE",
            title="Registro CAA ausente",
            category=self.category,
            severity=Severity.INFO,
            description=f"O domínio `{domain}` não define registros CAA.",
            impact=(
                "Sem CAA, qualquer Autoridade Certificadora pode emitir certificados "
                "para o seu domínio, ampliando o risco de emissão indevida."
            ),
            recommendation=(
                "Publique um registro CAA restringindo a emissão às CAs autorizadas, "
                'ex.: `0 issue "letsencrypt.org"`.'
            ),
            references=(ref.RFC_CAA,),
        )

    def _check_dnssec(self, resolver: dns.resolver.Resolver, domain: str) -> Iterable[Finding]:
        try:
            resolver.resolve(domain, "DNSKEY")
            return  # zona assinada — ok
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException:
            return
        yield Finding(
            id="DNSSEC_AUSENTE",
            title="DNSSEC não detectado",
            category=self.category,
            severity=Severity.INFO,
            description=f"Não foram encontrados registros DNSKEY para `{domain}` (zona provavelmente não assinada).",
            impact=(
                "Sem DNSSEC, respostas DNS podem ser forjadas (cache poisoning), "
                "redirecionando usuários para servidores maliciosos."
            ),
            recommendation="Avalie habilitar DNSSEC no provedor de DNS para assinar a zona.",
            references=(ref.RFC_DNSSEC,),
        )

    def _has_mx(self, resolver: dns.resolver.Resolver, domain: str) -> bool:
        """Verdadeiro apenas se o domínio RECEBE e-mail. Consulta inconclusiva
        (timeout/SERVFAIL) → ``False``, para não afirmar postura de e-mail sem
        certeza. Trata o *null MX* (RFC 7505): um único registro com troca ``.``
        significa 'este domínio NÃO recebe e-mail' — não deve exigir MTA-STS."""
        try:
            answer = resolver.resolve(domain, "MX")
        except dns.exception.DNSException:
            return False
        exchanges: list[str] = []
        for rdata in answer:
            tokens = str(rdata).split()
            exchanges.append(tokens[-1].rstrip(".") if tokens else "")
        if not exchanges:
            return False
        # Null MX (RFC 7505): único registro com troca vazia (".") → não recebe e-mail.
        return not (len(exchanges) == 1 and exchanges[0] == "")

    def _check_mta_sts(self, resolver: dns.resolver.Resolver, domain: str) -> Iterable[Finding]:
        txt = _txt_records(resolver, f"_mta-sts.{domain}")
        if txt is None:
            return  # inconclusivo
        if not any(r.lower().startswith("v=stsv1") for r in txt):
            yield Finding(
                id="MTA_STS_AUSENTE",
                title="MTA-STS não publicado",
                category=self.category,
                severity=Severity.LOW,
                description=f"O domínio `{domain}` recebe e-mail (tem MX), mas não publica uma política MTA-STS.",
                impact=(
                    "Sem MTA-STS, a entrega de e-mail para o seu domínio pode ser rebaixada "
                    "para uma conexão sem TLS por um atacante na rede (downgrade), expondo o "
                    "conteúdo das mensagens. O MTA-STS obriga os remetentes a usar TLS válido."
                ),
                recommendation=(
                    "Publique a política MTA-STS: o registro TXT `_mta-sts.<domínio>` "
                    "(`v=STSv1; id=...`) e o arquivo `/.well-known/mta-sts.txt` em "
                    "`mta-sts.<domínio>` com `mode: enforce`."
                ),
                references=(ref.RFC_MTA_STS,),
            )

    def _check_tls_rpt(self, resolver: dns.resolver.Resolver, domain: str) -> Iterable[Finding]:
        txt = _txt_records(resolver, f"_smtp._tls.{domain}")
        if txt is None:
            return  # inconclusivo
        if not any(r.lower().startswith("v=tlsrptv1") for r in txt):
            yield Finding(
                id="TLS_RPT_AUSENTE",
                title="TLS-RPT não publicado",
                category=self.category,
                severity=Severity.INFO,
                description=f"O domínio `{domain}` não publica TLS-RPT (relatórios de falha de TLS no e-mail).",
                impact=(
                    "Sem TLS-RPT você não recebe relatórios quando a entrega de e-mail falha "
                    "em negociar TLS — perdendo visibilidade de tentativas de downgrade e de "
                    "problemas de configuração no transporte de e-mail."
                ),
                recommendation=(
                    "Publique um registro TXT em `_smtp._tls.<domínio>` no formato "
                    "`v=TLSRPTv1; rua=mailto:...` para receber os relatórios."
                ),
                references=(ref.RFC_TLS_RPT,),
            )
