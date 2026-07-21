"""Análise de cabeçalhos de segurança HTTP.

Baseado no OWASP Secure Headers Project e nas referências do MDN. Avalia
presença e configuração dos principais cabeçalhos de defesa em profundidade.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.http import Probe
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

# Duração recomendada do HSTS. O OWASP Secure Headers Project recomenda
# max-age=63072000 (2 anos); o piso de elegibilidade para preload é 1 ano.
HSTS_ALVO = 63_072_000  # 2 anos (recomendação OWASP)
HSTS_PISO = 31_536_000  # 1 ano (mínimo para preload / boa prática)


@dataclass(frozen=True, slots=True)
class _SimpleHeader:
    """Especificação de um cabeçalho avaliado apenas por presença."""

    header: str
    finding_id: str
    title: str
    severity: Severity
    impact: str
    recommendation: str
    references: tuple[str, ...]


# Cabeçalhos cuja principal falha é simplesmente estarem ausentes.
_SIMPLE: tuple[_SimpleHeader, ...] = (
    _SimpleHeader(
        header="X-Content-Type-Options",
        finding_id="XCTO_AUSENTE",
        title="X-Content-Type-Options ausente",
        severity=Severity.LOW,
        impact=(
            "Sem 'nosniff', o navegador pode tentar adivinhar (MIME sniffing) o "
            "tipo de conteúdo e interpretar um arquivo como script, abrindo espaço "
            "para XSS a partir de uploads ou respostas mal tipadas."
        ),
        recommendation="Envie o cabeçalho `X-Content-Type-Options: nosniff` em todas as respostas.",
        references=(ref.MDN_XCTO, ref.OWASP_SECURE_HEADERS),
    ),
    _SimpleHeader(
        header="Referrer-Policy",
        finding_id="REFERRER_POLICY_AUSENTE",
        title="Referrer-Policy ausente",
        severity=Severity.LOW,
        impact=(
            "Sem política de referenciador, URLs internas (com tokens, IDs ou "
            "dados sensíveis no path/query) podem vazar para sites de terceiros no "
            "cabeçalho Referer."
        ),
        recommendation=(
            "Defina `Referrer-Policy: strict-origin-when-cross-origin` "
            "(ou `no-referrer` para o máximo de privacidade)."
        ),
        references=(ref.MDN_REFERRER, ref.OWASP_SECURE_HEADERS),
    ),
    _SimpleHeader(
        header="Permissions-Policy",
        finding_id="PERMISSIONS_POLICY_AUSENTE",
        title="Permissions-Policy ausente",
        severity=Severity.INFO,
        impact=(
            "Sem essa política, a página não restringe explicitamente recursos "
            "poderosos do navegador (câmera, microfone, geolocalização, etc.), "
            "ampliando o impacto de um eventual XSS."
        ),
        recommendation=(
            "Defina uma `Permissions-Policy` restritiva, desabilitando recursos "
            "não usados, ex.: `Permissions-Policy: camera=(), microphone=(), geolocation=()`."
        ),
        references=(ref.MDN_PERMISSIONS, ref.OWASP_SECURE_HEADERS),
    ),
    _SimpleHeader(
        header="Cross-Origin-Opener-Policy",
        finding_id="COOP_AUSENTE",
        title="Cross-Origin-Opener-Policy ausente",
        severity=Severity.INFO,
        impact=(
            "Sem COOP, a página compartilha o mesmo grupo de contexto de navegação "
            "com janelas de outras origens, facilitando ataques de canal lateral "
            "cross-origin (ex.: Spectre) e manipulação via window.opener."
        ),
        recommendation="Defina `Cross-Origin-Opener-Policy: same-origin` em páginas sensíveis.",
        references=(ref.MDN_COOP, ref.OWASP_SECURE_HEADERS),
    ),
)


class SecurityHeadersChecker(Checker):
    id = "security-headers"
    name = "Cabeçalhos de segurança HTTP"
    category = Category.HEADERS
    intrusive = False

    def run(self, ctx: ScanContext) -> Iterable[Finding]:
        probe = ctx.primary
        if not probe.ok:
            return  # transporte falhou; o motor registra o erro à parte

        serves_https = probe.final_url.startswith("https://") or ctx.target.is_https

        yield from self._check_hsts(probe, serves_https)
        yield from self._check_csp(probe)
        yield from self._check_frame_options(probe)
        for spec in _SIMPLE:
            if not probe.has_header(spec.header):
                yield Finding(
                    id=spec.finding_id,
                    title=spec.title,
                    category=self.category,
                    severity=spec.severity,
                    description=f"O cabeçalho `{spec.header}` não foi encontrado na resposta.",
                    impact=spec.impact,
                    recommendation=spec.recommendation,
                    references=spec.references,
                )
        yield from self._check_xss_protection(probe)

    def _check_hsts(self, probe: Probe, serves_https: bool) -> Iterable[Finding]:
        value = probe.header("Strict-Transport-Security")
        if not serves_https:
            return  # HSTS só faz sentido sobre HTTPS; navegadores ignoram via HTTP
        if value is None:
            yield Finding(
                id="HSTS_AUSENTE",
                title="HSTS (Strict-Transport-Security) ausente",
                category=self.category,
                severity=Severity.MEDIUM,
                description=(
                    "O site é servido por HTTPS, mas não envia o cabeçalho `Strict-Transport-Security`."
                ),
                impact=(
                    "Sem HSTS, a primeira visita (ou uma digitada sem https://) pode "
                    "ser interceptada e rebaixada para HTTP por um atacante na rede "
                    "(SSL stripping), expondo credenciais e cookies de sessão."
                ),
                recommendation=(
                    "Envie `Strict-Transport-Security: max-age=63072000; includeSubDomains` "
                    "(considere `; preload` após validar todos os subdomínios em HTTPS)."
                ),
                references=(ref.MDN_HSTS, ref.RFC_HSTS, ref.OWASP_HSTS_CHEATSHEET),
            )
            return

        max_age = _parse_max_age(value)
        if max_age is None or max_age < HSTS_PISO:
            yield Finding(
                id="HSTS_FRACO",
                title="HSTS com max-age insuficiente",
                category=self.category,
                severity=Severity.LOW,
                description="O HSTS está presente, mas com `max-age` curto demais.",
                evidence=f"Strict-Transport-Security: {value}",
                impact=(
                    "Uma janela HSTS curta reduz a proteção: fora do período, o "
                    "navegador volta a aceitar HTTP na primeira conexão."
                ),
                recommendation=(
                    f"Aumente para pelo menos `max-age={HSTS_ALVO}` (1 ano) e inclua `includeSubDomains`."
                ),
                references=(ref.MDN_HSTS, ref.OWASP_HSTS_CHEATSHEET),
            )
        elif "includesubdomains" not in value.lower():
            yield Finding(
                id="HSTS_SEM_SUBDOMINIOS",
                title="HSTS sem includeSubDomains",
                category=self.category,
                severity=Severity.INFO,
                description="O HSTS não cobre os subdomínios.",
                evidence=f"Strict-Transport-Security: {value}",
                impact=(
                    "Subdomínios sem HSTS podem ser usados para ataques de "
                    "rebaixamento e para plantar/ler cookies do domínio pai."
                ),
                recommendation="Adicione a diretiva `includeSubDomains` após validar todos os subdomínios em HTTPS.",
                references=(ref.MDN_HSTS,),
            )

    def _check_csp(self, probe: Probe) -> Iterable[Finding]:
        value = probe.header("Content-Security-Policy")
        if value is None:
            yield Finding(
                id="CSP_AUSENTE",
                title="Content-Security-Policy ausente",
                category=self.category,
                severity=Severity.MEDIUM,
                description="A resposta não define uma Content-Security-Policy.",
                impact=(
                    "A CSP é a defesa em profundidade mais eficaz contra XSS e "
                    "injeção de conteúdo. Sem ela, qualquer falha de saída não "
                    "escapada vira execução de script no navegador da vítima."
                ),
                recommendation=(
                    "Implante uma CSP restritiva (idealmente baseada em nonce/hash), "
                    "começando por `default-src 'self'` e liberando origens sob demanda. "
                    "Use o modo `Content-Security-Policy-Report-Only` para calibrar sem quebrar o site."
                ),
                references=(ref.MDN_CSP, ref.OWASP_CSP_CHEATSHEET),
            )
            return

        lowered = value.lower()
        fracos = [d for d in ("'unsafe-inline'", "'unsafe-eval'") if d in lowered]
        if fracos:
            yield Finding(
                id="CSP_DIRETIVA_INSEGURA",
                title="CSP contém diretivas inseguras",
                category=self.category,
                severity=Severity.LOW,
                description=f"A CSP presente usa {', '.join(fracos)}.",
                evidence=_truncate(value),
                impact=(
                    "`unsafe-inline` e `unsafe-eval` anulam boa parte da proteção da "
                    "CSP contra XSS, permitindo scripts inline e avaliação dinâmica."
                ),
                recommendation=(
                    "Remova `unsafe-inline`/`unsafe-eval` e adote nonces ou hashes "
                    "para os scripts legítimos."
                ),
                references=(ref.MDN_CSP, ref.OWASP_CSP_CHEATSHEET),
            )

    def _check_frame_options(self, probe: Probe) -> Iterable[Finding]:
        xfo = probe.header("X-Frame-Options")
        csp = (probe.header("Content-Security-Policy") or "").lower()
        if xfo is None and "frame-ancestors" not in csp:
            yield Finding(
                id="CLICKJACKING_SEM_PROTECAO",
                title="Sem proteção contra clickjacking",
                category=self.category,
                severity=Severity.MEDIUM,
                description=("Não há `X-Frame-Options` nem a diretiva `frame-ancestors` na CSP."),
                impact=(
                    "A página pode ser embutida em um <iframe> de um site malicioso "
                    "(clickjacking), induzindo o usuário a clicar em ações sem perceber."
                ),
                recommendation=(
                    "Defina `Content-Security-Policy: frame-ancestors 'none'` (ou "
                    "`'self'`) — abordagem moderna — e/ou `X-Frame-Options: DENY`."
                ),
                references=(ref.MDN_XFO, ref.OWASP_SECURE_HEADERS),
            )

    def _check_xss_protection(self, probe: Probe) -> Iterable[Finding]:
        value = probe.header("X-XSS-Protection")
        if value is not None and value.strip() != "0":
            yield Finding(
                id="XXSS_PROTECTION_LEGADO",
                title="X-XSS-Protection habilitado (legado)",
                category=self.category,
                severity=Severity.INFO,
                description="O cabeçalho `X-XSS-Protection` está ativo.",
                evidence=f"X-XSS-Protection: {value}",
                impact=(
                    "Esse filtro é obsoleto, foi removido dos navegadores modernos e, "
                    "no passado, o modo de bloqueio chegou a introduzir vulnerabilidades."
                ),
                recommendation=(
                    "Remova o cabeçalho ou defina `X-XSS-Protection: 0` e confie na CSP para mitigar XSS."
                ),
                references=(ref.OWASP_SECURE_HEADERS, ref.MDN_CSP),
            )


_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)


def _parse_max_age(value: str) -> int | None:
    match = _MAX_AGE_RE.search(value)
    return int(match.group(1)) if match else None


def _truncate(text: str, limit: int = 180) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"
