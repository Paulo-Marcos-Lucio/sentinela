"""Análise de cabeçalhos de segurança HTTP.

Baseado no OWASP Secure Headers Project e nas referências do MDN. Avalia
presença e configuração dos principais cabeçalhos de defesa em profundidade.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from sentinela.checks._util import truncate
from sentinela.checks.base import Checker
from sentinela.core.context import ScanContext
from sentinela.core.http import Probe
from sentinela.core.models import Category, Finding, Severity
from sentinela.knowledge import references as ref

# Duração recomendada do HSTS. O OWASP Secure Headers Project recomenda
# max-age=63072000 (2 anos); o piso de elegibilidade para preload é 1 ano.
HSTS_ALVO = 63_072_000  # 2 anos (recomendação OWASP)
HSTS_PISO = 31_536_000  # 1 ano (mínimo para preload / boa prática)

# Famílias de diretiva da CSP. Separá-las é o que permite o achado dizer ONDE está o
# problema: `unsafe-inline` em `script-src` permite executar script; em `style-src`
# permite injeção de CSS, que é outra coisa e tem outro tamanho.
_DIRETIVAS_DE_SCRIPT = frozenset({"script-src", "script-src-elem", "script-src-attr"})
_DIRETIVAS_DE_ESTILO = frozenset({"style-src", "style-src-elem", "style-src-attr"})


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
        # Hospedagem estática (GitHub Pages, S3, storage) NÃO emite cabeçalho: a política
        # vai em `<meta>` no HTML e o navegador a aplica. Ignorar isso rendia CSP_AUSENTE e
        # REFERRER_POLICY_AUSENTE falsos em todo site desse tipo.
        meta = _politicas_via_meta(probe.body_snippet)
        # Corpo truncado (teto de leitura, prazo estourado, conexão cortada) não autoriza
        # afirmar que uma política NÃO existe: a metatag pode estar nos bytes que não
        # chegaram. Medido: mesmo alvo, link rápido → CSP_VIA_META (informativo); link
        # lento com o corpo cortado → CSP_AUSENTE (média), afirmando ao cliente que não
        # há CSP num site que tem CSP, e recomendando implantar o que já está lá.
        corpo_parcial = probe.truncated and not meta

        yield from self._check_hsts(probe, serves_https)
        yield from self._check_csp(probe, meta.get("content-security-policy"), corpo_parcial)
        yield from self._check_frame_options(probe)
        for spec in _SIMPLE:
            if probe.has_header(spec.header):
                continue
            if spec.header.lower() in meta:
                continue  # declarado via <meta> e honrado pelo navegador — não é ausência
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
        yield from self._check_politica_via_meta(probe, meta)

    def _check_politica_via_meta(self, probe: Probe, meta: dict[str, str]) -> Iterable[Finding]:
        """Registra, de forma explícita, quais políticas vieram de `<meta>` e não de cabeçalho.

        Não é uma falha: `<meta>` é a única via disponível em hospedagem estática. Mas a
        entrega por `<meta>` tem limites REAIS (o navegador ignora `frame-ancestors`,
        `sandbox` e `report-uri`), e o relatório precisa dizer isso — é o que separa
        "protegido" de "parece protegido".
        """
        via_meta = [
            nome
            for cabecalho, nome in (
                ("content-security-policy", "Content-Security-Policy"),
                ("referrer-policy", "Referrer-Policy"),
            )
            if cabecalho in meta and not probe.has_header(cabecalho)
        ]
        if not via_meta:
            return
        csp_via_meta = "Content-Security-Policy" in via_meta
        impacto = (
            "Entregar a política por `<meta>` é legítimo e é a única opção em hospedagem "
            "estática (GitHub Pages, S3, Cloud Storage): o navegador aplica a política. "
        )
        if csp_via_meta:
            impacto += (
                "PORÉM, numa CSP entregue por `<meta>` o navegador IGNORA as diretivas "
                "`frame-ancestors`, `sandbox` e `report-uri` — elas só funcionam em cabeçalho. "
                "Ou seja: proteção contra clickjacking via CSP e coleta de violações NÃO estão "
                "ativas por esta via."
            )
        yield Finding(
            id="POLITICA_VIA_META",
            title="Política de segurança declarada via <meta>, não por cabeçalho HTTP",
            category=self.category,
            severity=Severity.INFO,
            description=f"Declarada(s) em `<meta>` no HTML: {', '.join(via_meta)}.",
            evidence=" · ".join(f"{n}: {truncate(meta[n.lower()])}" for n in via_meta),
            impact=impacto,
            recommendation=(
                "Se você controla o servidor/CDN, prefira o cabeçalho HTTP (cobre as diretivas "
                "que o `<meta>` não cobre e vale para respostas não-HTML). Em hospedagem "
                "estática, use `X-Frame-Options`/`frame-ancestors` via CDN ou aceite "
                "explicitamente essa limitação."
            ),
            references=(ref.MDN_CSP, ref.OWASP_SECURE_HEADERS),
        )

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
                    f"Aumente para pelo menos `max-age={HSTS_ALVO}` (2 anos) e inclua `includeSubDomains`."
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

    def _check_csp(
        self, probe: Probe, csp_meta: str | None, corpo_parcial: bool = False
    ) -> Iterable[Finding]:
        value = probe.header("Content-Security-Policy") or csp_meta
        if value is None:
            if corpo_parcial:
                yield Finding(
                    id="CSP_NAO_AVALIADA",
                    title="Presença de CSP não pôde ser confirmada (corpo incompleto)",
                    category=self.category,
                    severity=Severity.INFO,
                    description=(
                        "Não há cabeçalho `Content-Security-Policy`, e o HTML foi lido apenas "
                        f"parcialmente ({probe.bytes_lidos} bytes) — uma política declarada em "
                        "`<meta>` mais adiante no documento não teria sido vista."
                    ),
                    evidence=f"bytes lidos: {probe.bytes_lidos}",
                    impact=(
                        "Este achado NÃO afirma que falta CSP: afirma que não deu para "
                        "verificar. Afirmar ausência a partir de leitura parcial faz o mesmo "
                        "alvo mudar de veredito conforme a qualidade da rede."
                    ),
                    recommendation=(
                        "Repita a varredura numa conexão melhor ou com `--timeout` maior para "
                        "obter um veredito conclusivo sobre a CSP."
                    ),
                    references=(ref.MDN_CSP,),
                )
                return
            if probe.has_header("Content-Security-Policy-Report-Only"):
                yield Finding(
                    id="CSP_APENAS_REPORT_ONLY",
                    title="CSP presente apenas em modo report-only",
                    category=self.category,
                    severity=Severity.LOW,
                    description=(
                        "Existe `Content-Security-Policy-Report-Only`, mas nenhuma CSP em modo de "
                        "bloqueio (`Content-Security-Policy`)."
                    ),
                    impact=(
                        "Em report-only a política apenas reporta violações — não bloqueia nada. "
                        "Contra um XSS real, ela não oferece proteção alguma."
                    ),
                    recommendation=(
                        "Após calibrar com os relatórios, promova a política para o cabeçalho "
                        "`Content-Security-Policy` (modo de bloqueio)."
                    ),
                    references=(ref.MDN_CSP, ref.OWASP_CSP_CHEATSHEET),
                )
                return
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

        directives = _parse_csp(value)
        script = directives.get("script-src", directives.get("default-src", []))
        # `script-src-elem`/`script-src-attr` (CSP3) sobrepõem `script-src` para tags e
        # handlers inline. `unsafe-inline` em qualquer um deles é problema de SCRIPT.
        # CSP3: na presença de 'strict-dynamic' o navegador IGNORA allowlists de host,
        # esquemas e 'unsafe-inline' ao carregar script; na presença de nonce/hash (CSP2+)
        # ele já ignora 'unsafe-inline'. Nas duas formas esses tokens são FALLBACK de
        # compatibilidade — é exatamente a política que o Google recomenda em
        # csp.withgoogle.com/docs/strict-csp. Acusá-los é recomendar o enfraquecimento
        # de uma configuração correta.
        nonce_ou_hash = any(t.startswith("'nonce-") or t.startswith("'sha") for t in script)
        strict_dynamic = "'strict-dynamic'" in script

        def _inline_ignorado(diretiva: str) -> bool:
            if diretiva in ("script-src", "script-src-elem"):
                return nonce_ou_hash or strict_dynamic
            if diretiva == "default-src" and "script-src" not in directives:
                # Sem script-src, o default-src É a fonte de script. Só nonce/hash faz o
                # navegador ignorar 'unsafe-inline' também para o estilo inline que cai
                # no mesmo fallback; 'strict-dynamic' não tem efeito sobre style-src.
                return nonce_ou_hash
            return False

        # O achado tem que dizer em QUAL diretiva está o problema. Uma política com
        # `script-src 'self'` limpo e `unsafe-inline` só em `style-src` recebia um achado
        # cujo título, impacto e recomendação falavam de `script-src` — o cliente abria a
        # CSP, procurava no script-src, não achava nada, e perdia a confiança no laudo.
        # Detecção conservadora está certa; redação errada é falso positivo do mesmo jeito.
        script_afetado: list[str] = []
        # `unsafe-eval` só faz sentido para script: em `style-src` o token é inerte.
        if "'unsafe-eval'" in script:
            script_afetado.append("'unsafe-eval'")  # 'strict-dynamic' NÃO neutraliza eval
        if any(
            "'unsafe-inline'" in fontes and not _inline_ignorado(d)
            for d, fontes in directives.items()
            if d in _DIRETIVAS_DE_SCRIPT or (d == "default-src" and "script-src" not in directives)
        ):
            script_afetado.append("'unsafe-inline'")
        script_afetado.sort()

        estilo_afetado = any(
            "'unsafe-inline'" in fontes for d, fontes in directives.items() if d in _DIRETIVAS_DE_ESTILO
        ) or ("'unsafe-inline'" in directives.get("default-src", []) and "style-src" not in directives)

        if script_afetado:
            yield Finding(
                id="CSP_DIRETIVA_INSEGURA",
                title="CSP permite script inline ou avaliação dinâmica",
                category=self.category,
                severity=Severity.LOW,
                description="A fonte de scripts da CSP usa " + ", ".join(script_afetado) + ".",
                evidence=truncate(value),
                impact=(
                    "Em `script-src`, `unsafe-inline` e `unsafe-eval` anulam boa parte da "
                    "proteção da CSP contra XSS, permitindo scripts inline e avaliação dinâmica."
                ),
                recommendation=(
                    "Remova `unsafe-inline`/`unsafe-eval` da fonte de scripts e adote nonces "
                    "ou hashes para os scripts legítimos."
                ),
                references=(ref.MDN_CSP, ref.OWASP_CSP_CHEATSHEET),
            )
        elif estilo_afetado:
            # Só entra quando o script está limpo: senão seria o mesmo aviso duas vezes.
            yield Finding(
                id="CSP_ESTILO_INLINE",
                title="CSP permite estilo inline (style-src 'unsafe-inline')",
                category=self.category,
                severity=Severity.LOW,
                description=(
                    "A CSP usa `'unsafe-inline'` na fonte de ESTILOS. A fonte de scripts "
                    "está limpa — a proteção contra XSS de script continua de pé."
                ),
                evidence=truncate(value),
                impact=(
                    "Estilo inline liberado permite injeção de CSS: dado sensível já presente "
                    "na página (um token num atributo, por exemplo) pode ser exfiltrado por "
                    "seletor de atributo combinado com `background-image`. Depende de existir "
                    "um ponto de injeção — é bem menor que execução de script, e por isso "
                    "aparece como oportunidade de endurecimento, não como falha de proteção."
                ),
                recommendation=(
                    "Se o site não depende de `style=` inline, troque `'unsafe-inline'` por "
                    "nonce/hash em `style-src`. Se depender (é comum com CSS-in-JS), documente "
                    "como risco aceito — não mexa no `script-src`, que já está correto."
                ),
                references=(ref.MDN_CSP, ref.OWASP_CSP_CHEATSHEET),
            )

        yield from self._check_csp_sources(value, directives, strict_dynamic)

    def _check_csp_sources(
        self, value: str, directives: dict[str, list[str]], strict_dynamic: bool
    ) -> Iterable[Finding]:
        """Análise profunda de diretivas (estilo CSP Evaluator): curinga em script-src,
        object-src/base-uri ausentes — bypasses clássicos que passam despercebidos."""
        script = directives.get("script-src", directives.get("default-src"))
        if script is not None and not strict_dynamic:
            curingas = sorted(
                {t for t in script if t in ("*", "http:", "https:", "data:", "http://*", "https://*")}
            )
            if curingas:
                yield Finding(
                    id="CSP_WILDCARD_PERMISSIVO",
                    title="CSP com origem curinga em script-src",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    description=f"A fonte de scripts da CSP inclui curinga(s): {', '.join(curingas)}.",
                    evidence=truncate(value),
                    impact=(
                        "Um curinga (`*`, `https:`, `data:`) em `script-src` permite carregar script "
                        "de praticamente qualquer origem, esvaziando a proteção da CSP contra XSS."
                    ),
                    recommendation=(
                        "Restrinja `script-src` a origens específicas (idealmente nonce/hash), "
                        "removendo curingas e esquemas amplos."
                    ),
                    references=(ref.MDN_CSP, ref.OWASP_CSP_CHEATSHEET),
                )
        default = directives.get("default-src", [])
        if "object-src" not in directives and "'none'" not in default:
            yield Finding(
                id="CSP_SEM_OBJECT_SRC",
                title="CSP sem object-src 'none'",
                category=self.category,
                severity=Severity.LOW,
                description="A CSP não define `object-src 'none'` (nem um `default-src 'none'`).",
                impact=(
                    "Sem `object-src 'none'`, plugins/embeds (`<object>`, `<embed>`) podem ser "
                    "injetados e usados como vetor de execução — um bypass clássico de CSP."
                ),
                recommendation="Adicione `object-src 'none'` à política.",
                references=(ref.OWASP_CSP_CHEATSHEET,),
            )
        if "base-uri" not in directives:
            yield Finding(
                id="CSP_SEM_BASE_URI",
                title="CSP sem base-uri",
                category=self.category,
                severity=Severity.LOW,
                description="A CSP não define a diretiva `base-uri`.",
                impact=(
                    "Sem `base-uri`, uma injeção de `<base>` pode reescrever a resolução de URLs "
                    "relativas da página, desviando scripts e recursos para um servidor do atacante."
                ),
                recommendation="Adicione `base-uri 'self'` (ou `'none'`) à política.",
                references=(ref.OWASP_CSP_CHEATSHEET,),
            )

    def _check_frame_options(self, probe: Probe) -> Iterable[Finding]:
        xfo = probe.header("X-Frame-Options")
        # DELIBERADO: só a CSP de CABEÇALHO conta aqui. Numa CSP entregue por
        # `<meta http-equiv>` o navegador IGNORA `frame-ancestors` — aceitar a meta
        # aqui transformaria um site desprotegido contra clickjacking em "sem achado".
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

# Teto de atributos por tag (mesma defesa de O(n²) do checks/content.py) e teto de HTML
# varrido: as metas de política ficam no `<head>`, não no fim de uma página de 256 KB.
_META_TAG_RE = re.compile(r"<meta\b[^>]{0,2048}>", re.IGNORECASE)
_META_ATTR_RE = re.compile(r"""\b([a-z][a-z-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""", re.IGNORECASE)
_META_SCAN_CAP = 65_536


def _politicas_via_meta(body: str) -> dict[str, str]:
    """Políticas de segurança declaradas por `<meta>` no HTML, em ``{cabeçalho: valor}``.

    Só reconhece o que o navegador REALMENTE aplica por essa via: `Content-Security-Policy`
    (via ``http-equiv``) e `Referrer-Policy` (via ``name="referrer"``). Vale a primeira
    ocorrência de cada uma, que é a que o navegador usa como política base.

    A lista é fechada de propósito. HSTS, X-Frame-Options, X-Content-Type-Options,
    Permissions-Policy e COOP declarados por `<meta>` são IGNORADOS pelo navegador —
    aceitá-los aqui trocaria um falso positivo por um falso NEGATIVO, que é pior.
    """
    politicas: dict[str, str] = {}
    for tag in _META_TAG_RE.findall(body[:_META_SCAN_CAP]):
        atributos = {
            m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "")
            for m in _META_ATTR_RE.finditer(tag)
        }
        conteudo = atributos.get("content", "").strip()
        if not conteudo:
            continue
        equiv = atributos.get("http-equiv", "").strip().lower()
        nome = atributos.get("name", "").strip().lower()
        if equiv == "content-security-policy":
            politicas.setdefault("content-security-policy", conteudo)
        elif nome == "referrer":
            politicas.setdefault("referrer-policy", conteudo)
    return politicas


def _parse_max_age(value: str) -> int | None:
    match = _MAX_AGE_RE.search(value)
    return int(match.group(1)) if match else None


def _parse_csp(value: str) -> dict[str, list[str]]:
    """CSP em ``{diretiva: [fontes]}`` (tudo minúsculo), para análise de diretivas."""
    directives: dict[str, list[str]] = {}
    for parte in value.split(";"):
        tokens = parte.split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    return directives
