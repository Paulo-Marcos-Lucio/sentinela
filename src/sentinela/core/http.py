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
    truncated: bool = False
    """O corpo veio INCOMPLETO (teto de leitura, prazo estourado ou conexão cortada).

    Existe para uma regra só, e ela é a diferença entre relatório confiável e
    relatório perigoso: **nenhuma checagem pode AFIRMAR ausência a partir de um corpo
    truncado.** Uma metatag de CSP que ficou fora dos bytes lidos não é uma CSP que
    não existe — mas o achado dizia, com severidade média, "a resposta não define uma
    Content-Security-Policy". Numa rede pior, o mesmo alvo mudava de achado.
    """
    bytes_lidos: int = 0
    """Bytes de corpo efetivamente lidos, para o relatório poder mostrar a conta."""

    @property
    def ok(self) -> bool:
        """Verdadeiro se a requisição completou sem erro de transporte."""
        return self.error is None

    @property
    def corpo_confiavel(self) -> bool:
        """Verdadeiro quando dá para afirmar ausência de algo com base no corpo."""
        return self.ok and not self.truncated

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
            # O default do httpx é trust_env=True, e isso fazia a varredura herdar
            # HTTP_PROXY/HTTPS_PROXY/NO_PROXY e SSL_CERT_FILE do ambiente SEM registrar
            # nada no relatório. Efeito medido: com um proxy quebrado exportado, um site
            # no ar virava ALVO_INACESSIVEL (alta) e a nota era tetada em F; com um proxy
            # de inspeção corporativo, o relatório saía inteiro e ERRADO, em silêncio.
            # Um diagnóstico tem que medir o alvo, não a estação de trabalho.
            trust_env=False,
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
        truncado = False
        lidos = 0

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
                            #
                            # E falhamos ALTO. Antes disto o laço só dava `break` e o
                            # Probe voltava como um 3xx de corpo vazio — que as checagens
                            # liam como "resposta boa, sem nada dentro" e transformavam
                            # numa enxurrada de achados de ausência falsos. Basta um
                            # Pi-hole devolvendo 0.0.0.0, um DNS split-horizon ou uma VPN
                            # para o resolvedor da máquina disparar isso, e aí o mesmo
                            # alvo rende relatórios diferentes em máquinas diferentes.
                            return Probe(
                                url=url,
                                status_code=status,
                                headers=resp_headers,
                                final_url=final_url,
                                redirect_chain=tuple(chain),
                                error=(
                                    "RedirecionamentoBloqueado: o alvo redirecionou para "
                                    f"{next_url}, que o resolvedor desta máquina aponta para "
                                    "endereço interno/não roteável. A varredura parou aqui em "
                                    "vez de seguir (guarda anti-SSRF) — confira o DNS desta "
                                    "máquina antes de ler o resultado."
                                ),
                            )
                        current = next_url
                        continue

                    body_snippet, truncado, lidos = self._read_capped(response, cap)
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
            truncated=truncado,
            bytes_lidos=lidos,
        )

    def _read_capped(self, response: httpx.Response, cap: int) -> tuple[str, bool, int]:
        """Lê no máximo ``cap`` bytes do corpo. Devolve ``(texto, truncado, bytes)``.

        O ``truncado`` é o que impede a leitura parcial de virar afirmação de ausência.
        São duas formas de vir incompleto, e as duas contam: bater no teto ou a conexão
        cair no meio. Além delas, comparamos com ``Content-Length``:
        um servidor que anuncia 80 KB e entrega 30 KB entregou um corpo parcial mesmo
        sem nenhuma dessas condições ter disparado aqui.
        """
        chunks: list[bytes] = []
        total = 0
        truncado = False
        try:
            for chunk in response.iter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total >= cap:
                    truncado = True
                    break
        except (httpx.HTTPError, OSError):
            truncado = True  # conexão cortada no meio: o que temos é parcial
        anunciado = _content_length(response)
        if anunciado is not None and total < anunciado:
            truncado = True
        return _decode_body(chunks, cap, response), truncado, total

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

    Política de falha: FECHADO. Se o nome não resolve, não há como afirmar que ele é
    externo, e a guarda bloqueia. Falhar aberto deixaria uma janela entre a checagem
    (esta resolução) e a resolução que o ``httpx`` faz depois — o intervalo em que vive
    o DNS rebinding. O custo é parar a cadeia num redirecionamento cujo DNS falhou por
    outro motivo; nesse caso a requisição seguinte falharia de qualquer jeito.
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
        return True  # não resolveu → não seguimos (falha-fechado)
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


def _content_length(response: httpx.Response) -> int | None:
    """``Content-Length`` como inteiro, ou ``None`` se ausente/inválido."""
    headers = getattr(response, "headers", None)
    bruto = headers.get("content-length") if headers is not None else None
    if bruto is None:
        return None
    try:
        return int(bruto.strip())
    except ValueError:
        return None


def _decode_body(chunks: list[bytes], cap: int, response: httpx.Response) -> str:
    """Decodifica os bytes já lidos (mesmo que parciais por reset/prazo), tolerando
    corpos binários/encoding inválido (``errors="replace"`` nunca levanta exceção)."""
    raw = b"".join(chunks)[:cap]
    return raw.decode(response.encoding or "utf-8", "replace")


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
