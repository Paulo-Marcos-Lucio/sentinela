"""Motor de varredura: orquestra as checagens sobre um alvo."""

from __future__ import annotations

import platform
import ssl
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
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

        ctx = ScanContext(
            target=target,
            client=client,
            config=config,
            primary=primary,
            http_probe=http_probe,
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
