"""Motor de varredura: orquestra as checagens sobre um alvo."""

from __future__ import annotations

import platform
import ssl
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone

from sentinela.checks.base import Checker
from sentinela.core.config import ScanConfig
from sentinela.core.context import ScanContext
from sentinela.core.http import HttpClient, Probe
from sentinela.core.models import Category, Finding, ScanError, ScanResult, Severity, Target
from sentinela.core.registry import build_checkers
from sentinela.version import __version__

# Callback opcional de progresso: recebe (check_id, nome).
ProgressCallback = Callable[[str, str], None]

_MAX_WORKERS = 8

# Corpo da resposta primária: teto maior que o padrão (4 KB) para que a análise de
# conteúdo (mixed content, SRI, formulários) enxergue o <head> e os <script>/<link>
# reais da página. Ainda limitado — o download continua interrompido por streaming.
_PRIMARY_BODY_CAP = 262_144  # 256 KB


def condicoes_de_execucao() -> dict[str, str]:
    """Carimbo das condições da máquina que rodou a varredura.

    Cada item aqui é uma variável que JÁ MUDOU um achado em teste de campo:
    o OpenSSL decide se dá para testar TLS 1.0/1.1, o resolvedor decide se as
    checagens de DNS rodam, e o relógio decide a validade do certificado.
    """
    ambiente = {
        "python": platform.python_version(),
        "openssl": ssl.OPENSSL_VERSION,
        "sistema": f"{platform.system()} {platform.release()}",
        "relogio_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        import dns.resolver

        ns = dns.resolver.Resolver().nameservers[:3]
        ambiente["resolvedor_dns"] = ", ".join(str(n) for n in ns) or "não configurado"
    except Exception:  # noqa: BLE001 - o carimbo nunca derruba a varredura
        ambiente["resolvedor_dns"] = "indisponível"
    return ambiente


# Status que denunciam bloqueio por WAF/CDN/gateway (não é a aplicação respondendo):
# autenticação exigida, acesso negado, excesso de requisições, serviço indisponível.
_STATUS_BLOQUEIO = frozenset({401, 403, 429, 503})
# Marcas típicas de página de desafio/bloqueio de borda (cabeçalho ou corpo).
_ASSINATURAS_BLOQUEIO = (
    "cf-mitigated",
    "cf-ray",
    "just a moment",
    "attention required",
    "access denied",
    "akamai",
    "incapsula",
    "captcha",
    "cloudfront",
    "request blocked",
    "forbidden",
)


@dataclass(frozen=True, slots=True)
class _Situacao:
    """O que a resposta primária REALMENTE é, para gatear as checagens do alvo."""

    avaliar_cabecalhos: bool
    avaliar_documento: bool
    finding: Finding | None
    bloqueado: bool


def _host_de(url: str) -> str:
    from urllib.parse import urlsplit

    return (urlsplit(url).hostname or "").lower()


def _base_registravel(host: str) -> str:
    labels = host.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _classificar_primaria(primary: Probe, target: Target) -> _Situacao:
    """Classifica a resposta principal ANTES de tratá-la como "o alvo".

    A causa-raiz de uma cascata inteira de falsos positivos (auditoria 2026-08-28, classe
    C2/FN-01): o motor tomava qualquer coisa que voltasse — um 403 de WAF, um desafio da
    Cloudflare, um `application/json`, um redirect para outro host — como se fosse a página
    HTML do alvo, e as checagens de ausência (CSP_AUSENTE, HSTS_AUSENTE, CLICKJACKING...)
    laudavam a página ERRADA, em silêncio. Aqui isso é decidido UMA vez e vira contexto
    explícito, nunca silêncio.
    """
    status = primary.status_code
    if status >= 400:
        blob = " ".join(
            (
                primary.header("Server") or "",
                primary.header("cf-mitigated") or "",
                primary.header("cf-ray") or "",
                primary.body_snippet[:2000],
            )
        ).lower()
        bloqueio = status in _STATUS_BLOQUEIO or any(a in blob for a in _ASSINATURAS_BLOQUEIO)
        if bloqueio:
            finding = Finding(
                id="ALVO_BLOQUEADO",
                title="Resposta principal é uma página de bloqueio (WAF/CDN), não o alvo",
                category=Category.TRANSPORT,
                severity=Severity.INFO,
                description=(
                    f"A requisição principal recebeu HTTP {status} de uma camada de borda "
                    "(WAF/CDN/gateway), não da aplicação."
                ),
                evidence=f"HTTP {status} · {(primary.header('Server') or 'sem Server')}",
                impact=(
                    "Os cabeçalhos e o conteúdo desta resposta são da página de bloqueio, não do "
                    "site. Afirmar 'CSP ausente', 'HSTS ausente' ou 'sem proteção contra "
                    "clickjacking' a partir dela seria laudar o objeto errado — por isso essas "
                    "checagens de documento foram suprimidas nesta varredura."
                ),
                recommendation=(
                    "Reexecute a partir de um IP/User-Agent autorizado (allowlist do WAF) para "
                    "avaliar a aplicação real; ou trate este resultado apenas como sinal de que a "
                    "borda bloqueou o scanner."
                ),
            )
        else:
            finding = Finding(
                id="RESPOSTA_DE_ERRO",
                title=f"Resposta principal é um erro HTTP {status}",
                category=Category.TRANSPORT,
                severity=Severity.INFO,
                description=(
                    f"A URL do alvo respondeu HTTP {status}. A página de erro não é a aplicação: "
                    "as checagens de documento foram suprimidas para não laudar cabeçalhos que "
                    "são da página de erro."
                ),
                evidence=f"HTTP {status}",
                impact=(
                    "Cabeçalhos e conteúdo de uma página de erro não representam a superfície "
                    "real do alvo; afirmar ausências a partir deles produz laudo enganoso."
                ),
                recommendation="Confirme a URL correta do alvo e reexecute a varredura.",
            )
        return _Situacao(False, False, finding, bloqueado=True)

    host_final = _host_de(primary.final_url or target.url)
    if host_final and _base_registravel(host_final) != _base_registravel(target.host.lower()):
        finding = Finding(
            id="ALVO_REDIRECIONADO_OUTRO_HOST",
            title="O alvo redirecionou para outro host — o laudo passa a ser desse host",
            category=Category.TRANSPORT,
            severity=Severity.INFO,
            description=(
                f"A URL do alvo ({target.host}) redirecionou para `{host_final}`. As checagens "
                "abaixo avaliaram a resposta do host final, não a do host pedido."
            ),
            evidence=f"{target.host} → {host_final}",
            impact=(
                "Sem declarar a troca de host, o relatório atribuiria ao alvo achados que são de "
                "um terceiro (o destino do redirecionamento)."
            ),
            recommendation=(
                "Confirme se o redirecionamento para esse host é esperado; se quiser avaliar o "
                "host original, aponte a varredura diretamente para ele."
            ),
        )
        ctype = (primary.header("Content-Type") or "").split(";")[0].strip().lower()
        html = ctype == "" or ctype in ("text/html", "application/xhtml+xml")
        return _Situacao(True, html, finding, bloqueado=False)

    ctype = (primary.header("Content-Type") or "").split(";")[0].strip().lower()
    html = ctype == "" or ctype in ("text/html", "application/xhtml+xml")
    return _Situacao(True, html, None, bloqueado=False)


def run_scan(
    target: Target,
    config: ScanConfig,
    *,
    on_check: ProgressCallback | None = None,
) -> ScanResult:
    """Executa a varredura completa e devolve um :class:`ScanResult`.

    As checagens rodam em PARALELO (são I/O — HTTP/DNS/TLS independentes): o tempo
    total fica limitado pela checagem mais lenta, não pela soma. Uma falha em uma
    checagem é capturada em ``result.errors`` — nunca interrompe as demais.
    """
    result = ScanResult(
        target=target,
        intrusive=config.intrusive,
        tool_version=__version__,
        ambiente=condicoes_de_execucao(),
    )

    with HttpClient(
        timeout=config.timeout,
        user_agent=config.user_agent,
        verify_tls=config.verify_tls,
    ) as client:
        # primary (HTTPS) e a sonda HTTP são independentes → em paralelo (num host que
        # não responde, evita somar dois timeouts antes mesmo das checagens começarem).
        with ThreadPoolExecutor(max_workers=2) as pre_pool:
            primary_future = pre_pool.submit(
                lambda: client.get(target.url, max_body_bytes=_PRIMARY_BODY_CAP)
            )
            probe_future = pre_pool.submit(_probe_http, client, target)
            primary = primary_future.result()
            http_probe = probe_future.result()

        if not primary.ok:
            result.errors.append(ScanError("http", f"Falha ao acessar {target.url}: {primary.error}"))
            # Achado explícito: sem a resposta principal, a avaliação fica incompleta. Isso TETA
            # a nota em F (ver core/scoring.py) — a incapacidade de avaliar não pode virar nota boa.
            result.add(
                Finding(
                    id="ALVO_INACESSIVEL",
                    title="Alvo inacessível ou conexão não confiável",
                    category=Category.TRANSPORT,
                    severity=Severity.HIGH,
                    description=(
                        "A requisição principal ao alvo falhou (conexão recusada, timeout ou "
                        "certificado TLS não confiável)."
                    ),
                    evidence=str(primary.error),
                    impact=(
                        "Sem a resposta principal, as checagens de cabeçalhos, cookies, CORS e "
                        "conteúdo não puderam ser avaliadas. Do ponto de vista do usuário, o site "
                        "está inacessível por um canal confiável."
                    ),
                    recommendation=(
                        "Verifique a disponibilidade do alvo e a validade do certificado TLS; "
                        "reexecute a varredura após corrigir."
                    ),
                )
            )

        situacao = _classificar_primaria(primary, target) if primary.ok else None
        if situacao is not None and situacao.finding is not None:
            result.add(situacao.finding)

        ctx = ScanContext(
            target=target,
            client=client,
            config=config,
            primary=primary,
            http_probe=http_probe,
            avaliar_cabecalhos=situacao.avaliar_cabecalhos if situacao else False,
            avaliar_documento=situacao.avaliar_documento if situacao else False,
        )

        checkers = build_checkers(config)

        def _run_one(checker: Checker) -> tuple[str, list[Finding], ScanError | None]:
            if on_check is not None:
                on_check(checker.id, checker.name)
            try:
                return checker.id, list(checker.run(ctx)), None
            except Exception as exc:  # noqa: BLE001 - nenhuma checagem derruba a varredura
                return checker.id, [], ScanError(checker.id, f"{type(exc).__name__}: {exc}")

        # httpx.Client é thread-safe; cada checagem usa recursos independentes.
        with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(checkers) or 1)) as pool:
            for check_id, findings, error in pool.map(_run_one, checkers):  # ordem preservada
                if error is not None:
                    result.errors.append(error)
                    continue
                result.extend(findings)
                result.checks_run.append(check_id)

    result.finished_at = datetime.now(timezone.utc)
    return result


def _probe_http(client: HttpClient, target: Target) -> Probe | None:
    """Requisita a versão HTTP do host (sem redirecionar) p/ avaliar o upgrade a HTTPS.

    Para alvo já em ``http://`` numa porta não-padrão, a sonda vai na PORTA DO ALVO.
    Antes ela ia sempre na 80: o veredito de transporte de um app em ``:8080`` era
    decidido por um serviço DIFERENTE na porta 80 do mesmo host (contaminação cruzada).
    Para alvo ``https://``, a sonda continua na 80 de propósito — a pergunta é "a versão
    em texto aberto deste host faz upgrade?", e o texto aberto mora na 80.

    Quando a sonda FALHA, o Probe de erro é devolvido do mesmo jeito (em vez de ``None``):
    quem consome precisa distinguir "o servidor não redireciona" de "não consegui nem
    chegar na porta 80". As duas coisas produziam o mesmo silêncio, e o silêncio valia 8
    pontos a mais na nota — num firewall corporativo que bloqueia egress na 80, um site
    que serve texto aberto passava sem apontamento.
    """
    porta = f":{target.port}" if target.scheme == "http" and target.port != 80 else ""
    url = f"http://{target.host_for_url}{porta}/"
    return client.request("GET", url, follow_redirects=False)
