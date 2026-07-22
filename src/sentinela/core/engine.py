"""Motor de varredura: orquestra as checagens sobre um alvo."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from sentinela.checks.base import Checker
from sentinela.core.config import ScanConfig
from sentinela.core.context import ScanContext
from sentinela.core.http import HttpClient, Probe
from sentinela.core.models import Finding, ScanError, ScanResult, Target
from sentinela.core.registry import build_checkers
from sentinela.version import __version__

# Callback opcional de progresso: recebe (check_id, nome).
ProgressCallback = Callable[[str, str], None]

_MAX_WORKERS = 8


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
    result = ScanResult(target=target, intrusive=config.intrusive, tool_version=__version__)

    with HttpClient(
        timeout=config.timeout,
        user_agent=config.user_agent,
        verify_tls=config.verify_tls,
    ) as client:
        primary = client.get(target.url)
        if not primary.ok:
            result.errors.append(ScanError("http", f"Falha ao acessar {target.url}: {primary.error}"))

        http_probe = _probe_http(client, target)
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
    """Requisita a versão HTTP do host (sem redirecionar) p/ avaliar o upgrade a HTTPS."""
    url = f"http://{target.host_for_url}/"
    probe = client.request("GET", url, follow_redirects=False)
    return probe if probe.ok else None
