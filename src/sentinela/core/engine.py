"""Motor de varredura: orquestra as checagens sobre um alvo."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from sentinela.core.config import ScanConfig
from sentinela.core.context import ScanContext
from sentinela.core.http import HttpClient, Probe
from sentinela.core.models import ScanError, ScanResult, Target
from sentinela.core.registry import build_checkers
from sentinela.version import __version__

# Callback opcional de progresso: recebe (check_id, nome).
ProgressCallback = Callable[[str, str], None]


def run_scan(
    target: Target,
    config: ScanConfig,
    *,
    on_check: ProgressCallback | None = None,
) -> ScanResult:
    """Executa a varredura completa e devolve um :class:`ScanResult`.

    Uma falha em uma checagem individual é capturada e registrada em
    ``result.errors`` — nunca interrompe a varredura das demais.
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

        for checker in build_checkers(config):
            if on_check is not None:
                on_check(checker.id, checker.name)
            try:
                findings = list(checker.run(ctx))
            except Exception as exc:  # noqa: BLE001 - resiliência: nenhuma checagem derruba a varredura
                result.errors.append(ScanError(checker.id, f"{type(exc).__name__}: {exc}"))
                continue
            result.extend(findings)
            result.checks_run.append(checker.id)

    result.finished_at = datetime.now(timezone.utc)
    return result


def _probe_http(client: HttpClient, target: Target) -> Probe | None:
    """Requisita a versão HTTP do host (sem redirecionar) p/ avaliar o upgrade a HTTPS."""
    url = f"http://{target.host_for_url}/"
    probe = client.request("GET", url, follow_redirects=False)
    return probe if probe.ok else None
