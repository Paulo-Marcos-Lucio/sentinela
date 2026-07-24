"""Cliente HTTP e abstração de resposta ("sonda").

As checagens nunca falam com ``httpx`` diretamente: elas recebem objetos
:class:`Probe`. Isso mantém a camada de rede num único lugar (timeouts, headers,
tratamento de erro) e torna cada checagem testável apenas construindo um
``Probe`` na mão, sem tocar na rede.

Duas decisões de segurança da própria ferramenta ficam aqui:

* **Guarda anti-SSRF**: os redirecionamentos são seguidos manualmente e cada
  salto é validado — um alvo hostil não consegue desviar a varredura para
  infraestrutura interna (loopback, redes privadas, link-local). O alvo inicial,
  escolhido pelo operador, nunca é bloqueado (varredura interna legítima).
* **Corpo limitado de fato**: o download é feito por streaming e interrompido em
  ``max_body_bytes`` — um alvo não consegue nos fazer baixar gigabytes.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field

import httpx

from sentinela.version import __version__

USER_AGENT = f"Sentinela/{__version__} (+https://github.com/Paulo-Marcos-Lucio/sentinela)"

_MAX_REDIRECTS = 10


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
    """Wrapper fino sobre ``httpx.Client`` com defaults seguros."""

    timeout: float = 15.0
    user_agent: str = USER_AGENT
    verify_tls: bool = True
    max_body_bytes: int = 4096
    _client: httpx.Client = field(init=False)

    def __post_init__(self) -> None:
        self._client = httpx.Client(
            timeout=self.timeout,
            verify=self.verify_tls,
            # Redirecionamentos são seguidos manualmente em request(), com guarda anti-SSRF.
            follow_redirects=False,
            headers={"User-Agent": self.user_agent, "Accept": "*/*"},
            # Pool de conexões (não limita o tamanho do corpo — isso é feito por streaming).
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
        max_body_bytes: int | None = None,
    ) -> Probe:
        """Executa uma requisição e devolve um :class:`Probe`, nunca uma exceção.

        Redirecionamentos são seguidos manualmente (até ``_MAX_REDIRECTS``), com
        cada destino validado contra a guarda anti-SSRF. Erros de rede, TLS ou de
        URL viram um ``Probe`` com ``error`` preenchido. ``max_body_bytes`` permite
        a uma checagem específica (ex.: análise de HTML) ler mais do corpo que o
        teto padrão, sem afrouxar o limite das demais requisições.
        """
        cap = self.max_body_bytes if max_body_bytes is None else max_body_bytes
        chain: list[str] = []
        current = url
        status = 0
        resp_headers: dict[str, str] = {}
        set_cookies: list[str] = []
        body_snippet = ""
        final_url = url
        elapsed_ms = 0.0

        try:
            for hop in range(_MAX_REDIRECTS + 1):
                with self._client.stream(method, current, headers=headers) as response:
                    chain.append(current)
                    status = response.status_code
                    resp_headers = dict(response.headers)
                    final_url = str(response.url)
                    for key, value in response.headers.multi_items():
                        if key.lower() == "set-cookie":
                            set_cookies.append(value)

                    location = response.headers.get("location")
                    is_redirect = 300 <= status < 400 and location is not None
                    if follow_redirects and is_redirect and hop < _MAX_REDIRECTS:
                        next_url = str(response.url.join(location))
                        if _host_is_blocked(httpx.URL(next_url).host):
                            # Guarda anti-SSRF: não seguimos para host interno/privado.
                            break
                        current = next_url
                        continue

                    body_snippet = self._read_capped(response, cap)
                    elapsed_ms = _safe_elapsed(response)
                    break
        except (httpx.HTTPError, httpx.InvalidURL, OSError) as exc:
            return Probe(url=url, status_code=0, headers={}, error=_describe(exc))

        return Probe(
            url=url,
            status_code=status,
            headers=resp_headers,
            body_snippet=body_snippet,
            final_url=final_url,
            redirect_chain=tuple(chain),
            set_cookies=tuple(set_cookies),
            elapsed_ms=elapsed_ms,
        )

    def _read_capped(self, response: httpx.Response, cap: int) -> str:
        """Lê no máximo ``cap`` bytes do corpo, interrompendo o download."""
        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in response.iter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total >= cap:
                    break
        except (httpx.HTTPError, OSError):
            return ""
        raw = b"".join(chunks)[:cap]
        return raw.decode(response.encoding or "utf-8", "replace")

    def get(self, url: str, **kwargs: object) -> Probe:
        return self.request("GET", url, **kwargs)  # type: ignore[arg-type]

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _host_is_blocked(host: str | None) -> bool:
    """Verdadeiro se o host (literal ou resolvido) cai em faixa não-roteável/interna.

    Aplicada apenas a destinos de redirecionamento — nunca ao alvo inicial, que é
    a escolha explícita do operador (permite varredura de hosts internos).
    """
    if not host:
        return False
    try:
        return _ip_blocked(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if _ip_blocked(ip):
            return True
    return False


def _ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _safe_elapsed(response: httpx.Response) -> float:
    try:
        return response.elapsed.total_seconds() * 1000
    except RuntimeError:
        return 0.0


def _describe(exc: Exception) -> str:
    """Mensagem de erro curta e legível a partir de uma exceção."""
    name = type(exc).__name__
    detail = str(exc).strip()
    return f"{name}: {detail}" if detail else name
