"""Fixtures e utilitários de teste — tudo offline, sem tocar na rede."""

from __future__ import annotations

from collections.abc import Callable

from sentinela.core.config import ScanConfig
from sentinela.core.context import ScanContext
from sentinela.core.http import Probe
from sentinela.core.models import Target
from sentinela.core.target import parse_target

Handler = Callable[[str, str, dict[str, str] | None], Probe | None]


def make_target(url: str = "https://example.com/") -> Target:
    return parse_target(url)


def make_probe(
    *,
    headers: dict[str, str] | None = None,
    status: int = 200,
    body: str = "",
    set_cookies: tuple[str, ...] = (),
    final_url: str = "https://example.com/",
    error: str | None = None,
) -> Probe:
    return Probe(
        url=final_url,
        status_code=status,
        headers=headers or {},
        body_snippet=body,
        final_url=final_url,
        set_cookies=set_cookies,
        error=error,
    )


class FakeClient:
    """Cliente HTTP falso: responde a partir de um handler ou de um probe padrão."""

    def __init__(self, handler: Handler | None = None, default: Probe | None = None) -> None:
        self.handler = handler
        self.default = default if default is not None else make_probe()
        self.calls: list[tuple[str, str, dict[str, str] | None]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        # Precisa aceitar `max_body_bytes` para poder substituir o HttpClient DENTRO do
        # motor (o `run_scan` passa esse argumento na coleta primária). Sem ele, um teste
        # de motor "com cliente falso" explodia e acabava indo à internet de verdade.
        max_body_bytes: int | None = None,
    ) -> Probe:
        self.calls.append((method, url, headers))
        if self.handler is not None:
            resposta = self.handler(method, url, headers)
            if resposta is not None:
                return resposta
        return self.default

    def get(self, url: str, **kwargs: object) -> Probe:
        return self.request("GET", url, **kwargs)  # type: ignore[arg-type]

    def close(self) -> None:
        return

    def __enter__(self) -> FakeClient:
        return self

    def __exit__(self, *exc: object) -> None:
        return


def make_context(
    *,
    primary: Probe | None = None,
    http_probe: Probe | None = None,
    client: FakeClient | None = None,
    config: ScanConfig | None = None,
    target: Target | None = None,
) -> ScanContext:
    return ScanContext(
        target=target or make_target(),
        client=client or FakeClient(),  # type: ignore[arg-type]
        config=config or ScanConfig(),
        primary=primary if primary is not None else make_probe(),
        http_probe=http_probe,
    )
