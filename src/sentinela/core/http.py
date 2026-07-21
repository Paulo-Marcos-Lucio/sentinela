"""Cliente HTTP e abstração de resposta ("sonda").

As checagens nunca falam com ``httpx`` diretamente: elas recebem objetos
:class:`Probe`. Isso mantém a camada de rede num único lugar (timeouts, headers,
tratamento de erro) e torna cada checagem testável apenas construindo um
``Probe`` na mão, sem tocar na rede.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from sentinela.version import __version__

USER_AGENT = f"Sentinela/{__version__} (+https://github.com/Paulo-Marcos-Lucio/sentinela)"


@dataclass(frozen=True, slots=True)
class Probe:
    """Resultado normalizado e imutável de uma requisição HTTP.

    Cabeçalhos são expostos com acesso case-insensitive via :meth:`header`.
    """

    url: str
    status_code: int
    headers: dict[str, str]
    body_snippet: str = ""
    final_url: str = ""
    redirect_chain: tuple[str, ...] = ()
    set_cookies: tuple[str, ...] = ()
    error: str | None = None
    elapsed_ms: float = 0.0

    @property
    def ok(self) -> bool:
        """Verdadeiro se a requisição completou sem erro de transporte."""
        return self.error is None

    def header(self, name: str) -> str | None:
        """Busca um cabeçalho de forma case-insensitive."""
        target = name.lower()
        for key, value in self.headers.items():
            if key.lower() == target:
                return value
        return None

    def has_header(self, name: str) -> bool:
        return self.header(name) is not None


@dataclass(slots=True)
class HttpClient:
    """Wrapper fino sobre ``httpx.Client`` com defaults sensatos e seguros."""

    timeout: float = 15.0
    user_agent: str = USER_AGENT
    verify_tls: bool = True
    max_body_bytes: int = 4096
    _client: httpx.Client = field(init=False)

    def __post_init__(self) -> None:
        self._client = httpx.Client(
            timeout=self.timeout,
            verify=self.verify_tls,
            follow_redirects=True,
            headers={"User-Agent": self.user_agent, "Accept": "*/*"},
            # Limita o download: só precisamos de headers e de uma amostra do corpo.
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> Probe:
        """Executa uma requisição e devolve um :class:`Probe`, nunca uma exceção.

        Erros de rede/timeout/TLS viram ``Probe`` com ``error`` preenchido, para
        que uma checagem individual não derrube a varredura inteira.
        """
        try:
            response = self._client.request(
                method,
                url,
                headers=headers,
                follow_redirects=follow_redirects,
            )
        except httpx.HTTPError as exc:
            return Probe(url=url, status_code=0, headers={}, error=_describe(exc))

        body_snippet = ""
        try:
            body_snippet = response.text[: self.max_body_bytes]
        except (UnicodeDecodeError, httpx.HTTPError):
            body_snippet = ""

        set_cookies = tuple(v for k, v in response.headers.multi_items() if k.lower() == "set-cookie")
        chain = tuple(str(r.url) for r in response.history) + (str(response.url),)

        return Probe(
            url=url,
            status_code=response.status_code,
            headers=dict(response.headers),
            body_snippet=body_snippet,
            final_url=str(response.url),
            redirect_chain=chain,
            set_cookies=set_cookies,
            elapsed_ms=response.elapsed.total_seconds() * 1000,
        )

    def get(self, url: str, **kwargs: object) -> Probe:
        return self.request("GET", url, **kwargs)  # type: ignore[arg-type]

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _describe(exc: httpx.HTTPError) -> str:
    """Mensagem de erro curta e legível a partir de uma exceção httpx."""
    name = type(exc).__name__
    detail = str(exc).strip()
    return f"{name}: {detail}" if detail else name
